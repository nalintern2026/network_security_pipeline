"""
SBOM Service: Parse user-uploaded dependency files, build CycloneDX BOM, and check vulnerabilities via OSV API.
No static data or this project's dependencies are used—only the file content uploaded by the user.
Supports: requirements.txt, package.json, package-lock.json, yarn.lock, Pipfile, poetry.lock,
          Gemfile, Gemfile.lock, go.mod, Cargo.toml, Cargo.lock.
- SBOM format: CycloneDX (cyclonedx-python-lib)
- Vulnerability data: OSV API (https://api.osv.dev) - aggregates GitHub Advisories, PyPA, NVD, RustSec, etc.
"""
import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

import requests

# CycloneDX BOM generation (not Syft)
try:
    from cyclonedx.model.bom import Bom, BomMetaData
    from cyclonedx.model.component import Component, ComponentType
    from cyclonedx.model.tool import Tool
    from cyclonedx.output.json import JsonV1Dot6
    from packageurl import PackageURL
    CYCLONEDX_AVAILABLE = True
except ImportError:
    CYCLONEDX_AVAILABLE = False

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_VULNS_URL = "https://api.osv.dev/v1/vulns"

# Severity mapping from OSV/ecosystem/CVSS to normalized levels
SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Low",
    "UNSPECIFIED": "Medium",
}

# Remediation tips by severity (user-facing guidance)
SEVERITY_TIPS = {
    "Critical": [
        "Update immediately. Critical vulnerabilities often allow remote code execution or data breach.",
        "Apply the fix in a controlled environment first; test before production.",
        "Consider temporary mitigations (e.g., disable affected features) if immediate update is not possible.",
        "Notify your security team and stakeholders.",
    ],
    "High": [
        "Plan an update within 24–48 hours. High-severity issues can lead to significant impact.",
        "Review the CVE/NVD advisory for workarounds while preparing the update.",
        "Ensure your CI/CD pipeline runs security scans before deployment.",
        "Check if the vulnerability is exploitable in your deployment context.",
    ],
    "Medium": [
        "Schedule an update in the next sprint or maintenance window.",
        "Assess whether the vulnerability is exploitable in your use case.",
        "Pin dependencies to fixed versions in your lock file after updating.",
        "Add a TODO or ticket to track the fix.",
    ],
    "Low": [
        "Include in regular dependency update cycles.",
        "Document the finding for future maintenance.",
        "Consider updating when you next touch this dependency.",
    ],
    "Unknown": [
        "Severity could not be determined; check the advisory for details.",
        "Consider updating to a fixed version if one is published.",
    ],
}

# General remediation tips by vulnerability type (keyword-based)
VULN_TYPE_TIPS = {
    "xss": "Sanitize user input and use Content-Security-Policy headers.",
    "injection": "Use parameterized queries and input validation.",
    "rce": "Restrict network access and run with least privilege.",
    "dos": "Implement rate limiting and resource caps.",
    "ssrf": "Validate and restrict outbound URLs.",
    "auth": "Use strong authentication and session management.",
    "path traversal": "Validate and sanitize file paths; avoid user-controlled paths.",
    "prototype pollution": "Avoid merging user objects; use safe defaults.",
    "memory": "Ensure proper bounds checking; consider upgrading to patched version.",
    "bypass": "Implement defense in depth; validate all security checks.",
}


def _parse_requirements_txt(content: str) -> List[Dict[str, str]]:
    """Parse requirements.txt into list of {name, version, ecosystem}. Skip editable and VCS installs; use 'unknown' when no version."""
    deps = []
    for line in content.splitlines():
        raw = line.strip()
        line = raw.split("#")[0].strip()
        if not line or line.startswith("["):
            continue
        # Skip editable installs: -e /path or -e git+...
        if line.startswith("-e") or line.startswith("-e "):
            continue
        # Skip VCS / file installs (no reliable version without resolving)
        lower = line.lower()
        if any(lower.startswith(p) for p in ("git+", "hg+", "svn+", "bzr+")) or "file://" in lower:
            continue
        if line.startswith("-") and not re.match(r"^-[a-zA-Z0-9_.-]+\s*[=<>!~]", line):
            continue
        # package==1.2.3 or package>=1.0 or package~=1.0
        m = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~]+)\s*([^\s#,\[]+)", line)
        if m:
            name, _, version = m.group(1), m.group(2), m.group(3)
            deps.append({"name": name.lower().replace("_", "-"), "version": version, "ecosystem": "PyPI"})
        else:
            m = re.match(r"^([a-zA-Z0-9_.-]+)\s*$", line)
            if m:
                # No version specified: mark unknown and skip vulnerability scan later
                deps.append({"name": m.group(1).lower().replace("_", "-"), "version": "unknown", "ecosystem": "PyPI"})
    return deps


def _parse_package_json(content: str) -> List[Dict[str, str]]:
    """Parse package.json dependencies and devDependencies. Use 'unknown' when version is not a clear semver."""
    deps = []
    try:
        data = json.loads(content)
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            obj = data.get(key, {})
            if not isinstance(obj, dict):
                continue
            for name, ver in obj.items():
                if isinstance(ver, str):
                    # Strip ^ ~ and take first version-like part
                    version = ver.replace("^", "").replace("~", "").split("-")[0].split(" ")[0].strip()
                    if version and version[0].isdigit():
                        deps.append({"name": name, "version": version, "ecosystem": "npm"})
                    else:
                        # * or workspace: or link: etc.
                        deps.append({"name": name, "version": "unknown", "ecosystem": "npm"})
    except json.JSONDecodeError as e:
        logger.warning(f"package.json parse error: {e}")
    return deps


def _parse_pipfile(content: str) -> List[Dict[str, str]]:
    """Parse Pipfile [packages] section."""
    deps = []
    in_packages = False
    for line in content.splitlines():
        line = line.strip()
        if line == "[packages]":
            in_packages = True
            continue
        if in_packages and line.startswith("["):
            break
        if in_packages and "=" in line:
            name = line.split("=")[0].strip().strip('"').strip("'")
            ver_part = line.split("=", 1)[1].strip().strip('"').strip("'")
            version = "0.0.0"
            if ver_part and ver_part != "*":
                m = re.search(r"==\s*([^\s,]+)", ver_part)
                if m:
                    version = m.group(1)
            deps.append({"name": name.lower().replace("_", "-"), "version": version, "ecosystem": "PyPI"})
    return deps


def _parse_gemfile(content: str) -> List[Dict[str, str]]:
    """Parse Gemfile gem lines."""
    deps = []
    for line in content.splitlines():
        m = re.match(r'^\s*gem\s+["\']([^"\']+)["\'](?:\s*,\s*["\']([^"\']+)["\'])?', line)
        if m:
            name, version = m.group(1), m.group(2) or "0.0.0"
            deps.append({"name": name, "version": version, "ecosystem": "RubyGems"})
    return deps


def _parse_gomod(content: str) -> List[Dict[str, str]]:
    """Parse go.mod require block."""
    deps = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line == "require (":
            in_require = True
            continue
        if in_require and line == ")":
            break
        if in_require and line:
            parts = line.split()
            if len(parts) >= 2:
                mod, ver = parts[0], parts[1]
                deps.append({"name": mod, "version": ver.lstrip("v"), "ecosystem": "Go"})
    return deps


def _parse_cargo_toml(content: str) -> List[Dict[str, str]]:
    """Parse Cargo.toml [dependencies] section."""
    deps = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if line == "[dependencies]":
            in_deps = True
            continue
        if in_deps and line.startswith("["):
            break
        if in_deps and "=" in line and not line.startswith("#"):
            name = line.split("=")[0].strip().strip('"')
            ver_part = line.split("=", 1)[1].strip().strip('"').strip("'")
            version = "0.0.0"
            if ver_part:
                version = ver_part
            deps.append({"name": name, "version": version, "ecosystem": "crates.io"})
    return deps


def _parse_package_lock(content: str) -> List[Dict[str, str]]:
    """Parse package-lock.json packages (npm v2+ lockfile)."""
    deps = []
    try:
        data = json.loads(content)
        packages = data.get("packages", data.get("dependencies", {}))
        if not isinstance(packages, dict):
            return deps
        for key, pkg in packages.items():
            if key in ("", "node_modules"):
                continue
            if key.startswith("node_modules/"):
                name = key.replace("node_modules/", "").split("/")[-1]
            else:
                name = key
            version = pkg.get("version", "0.0.0") if isinstance(pkg, dict) else str(pkg)
            deps.append({"name": name, "version": version, "ecosystem": "npm"})
    except json.JSONDecodeError as e:
        logger.warning(f"package-lock.json parse error: {e}")
    return deps


def _parse_yarn_lock(content: str) -> List[Dict[str, str]]:
    """Parse yarn.lock - extract package@version blocks."""
    deps = []
    current_name = None
    seen = set()
    for line in content.splitlines():
        line = line.strip()
        if line.startswith('"') and "@" in line and ":" in line:
            m = re.match(r'"([^"@]+)@[^"]*"', line)
            if m:
                current_name = m.group(1)
        elif line.startswith("version ") and current_name:
            ver = line.split('"', 2)[1] if '"' in line else "0.0.0"
            key = f"{current_name}@{ver}"
            if key not in seen:
                seen.add(key)
                deps.append({"name": current_name, "version": ver, "ecosystem": "npm"})
            current_name = None
    return deps


def _parse_poetry_lock(content: str) -> List[Dict[str, str]]:
    """Parse poetry.lock [[package]] sections."""
    deps = []
    in_package = False
    name, version = None, "0.0.0"
    for line in content.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if name:
                deps.append({"name": name.lower().replace("_", "-"), "version": version, "ecosystem": "PyPI"})
            in_package = True
            name, version = None, "0.0.0"
        elif in_package and line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"').strip("'")
        elif in_package and line.startswith("version = "):
            version = line.split("=", 1)[1].strip().strip('"').strip("'")
        elif in_package and line.startswith("[") and not line.startswith("[[package]]"):
            if name:
                deps.append({"name": name.lower().replace("_", "-"), "version": version, "ecosystem": "PyPI"})
            in_package = False
    if in_package and name:
        deps.append({"name": name.lower().replace("_", "-"), "version": version, "ecosystem": "PyPI"})
    return deps


def _parse_gemfile_lock(content: str) -> List[Dict[str, str]]:
    """Parse Gemfile.lock GEM sections."""
    deps = []
    in_gems = False
    for line in content.splitlines():
        line = line.strip()
        if line == "GEM":
            in_gems = True
            continue
        if in_gems and line.startswith(" ") and "(" in line:
            m = re.match(r"\s+([a-zA-Z0-9_-]+)\s+\(([^)]+)\)", line)
            if m:
                deps.append({"name": m.group(1), "version": m.group(2), "ecosystem": "RubyGems"})
        elif in_gems and line and not line.startswith(" "):
            break
    return deps


def _parse_cargo_lock(content: str) -> List[Dict[str, str]]:
    """Parse Cargo.lock [[package]] sections."""
    deps = []
    in_package = False
    name, version = None, "0.0.0"
    for line in content.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if name:
                deps.append({"name": name, "version": version, "ecosystem": "crates.io"})
            in_package = True
            name, version = None, "0.0.0"
        elif in_package and line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"')
        elif in_package and line.startswith("version = "):
            version = line.split("=", 1)[1].strip().strip('"')
        elif in_package and line.startswith("[") and not line.startswith("[[package]]"):
            if name:
                deps.append({"name": name, "version": version, "ecosystem": "crates.io"})
            in_package = False
    if in_package and name:
        deps.append({"name": name, "version": version, "ecosystem": "crates.io"})
    return deps


def parse_dependency_file(filename: str, content: str) -> Tuple[List[Dict[str, str]], str]:
    """
    Parse dependency file and return (deps, ecosystem).
    deps: list of {name, version, ecosystem}
    """
    fn = filename.lower()
    if fn.endswith("requirements.txt") or fn == "requirements.txt":
        deps = _parse_requirements_txt(content)
        return deps, "PyPI"
    if fn.endswith("package.json"):
        deps = _parse_package_json(content)
        return deps, "npm"
    if fn.endswith("package-lock.json"):
        deps = _parse_package_lock(content)
        return deps, "npm"
    if fn.endswith("yarn.lock"):
        deps = _parse_yarn_lock(content)
        return deps, "npm"
    if fn.endswith("pipfile") or fn == "pipfile":
        deps = _parse_pipfile(content)
        return deps, "PyPI"
    if fn.endswith("poetry.lock"):
        deps = _parse_poetry_lock(content)
        return deps, "PyPI"
    if fn.endswith("gemfile") or fn == "gemfile":
        deps = _parse_gemfile(content)
        return deps, "RubyGems"
    if fn.endswith("gemfile.lock"):
        deps = _parse_gemfile_lock(content)
        return deps, "RubyGems"
    if fn.endswith("go.mod"):
        deps = _parse_gomod(content)
        return deps, "Go"
    if fn.endswith("cargo.toml"):
        deps = _parse_cargo_toml(content)
        return deps, "crates.io"
    if fn.endswith("cargo.lock"):
        deps = _parse_cargo_lock(content)
        return deps, "crates.io"
    return [], ""


def query_osv(package: str, version: str, ecosystem: str) -> List[Dict[str, Any]]:
    """Query OSV API for vulnerabilities. Handles pagination. Returns list of vuln objects."""
    all_vulns = []
    page_token = None
    try:
        while True:
            payload = {
                "package": {"name": package, "ecosystem": ecosystem},
                "version": version,
            }
            if page_token:
                payload["page_token"] = page_token
            resp = requests.post(OSV_API_URL, json=payload, timeout=20)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulns", [])
            all_vulns.extend(vulns)
            page_token = data.get("next_page_token")
            if not page_token:
                break
    except Exception as e:
        logger.warning(f"OSV query failed for {package}@{version}: {e}")
    return all_vulns


def _cvss_to_severity(score: float) -> str:
    """Map CVSS score to normalized severity."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _extract_severity(vuln: Dict) -> str:
    """Extract normalized severity from OSV vuln. Prefer CVSS score when available."""
    # Check severity array (CVSS) - most accurate
    for sev_obj in vuln.get("severity", []):
        stype = sev_obj.get("type", "")
        score_str = sev_obj.get("score", "")
        if "CVSS" in stype and score_str:
            try:
                score = float(score_str)
                return _cvss_to_severity(score)
            except (ValueError, TypeError):
                m = re.search(r"(\d+\.?\d*)", str(score_str))
                if m:
                    return _cvss_to_severity(float(m.group(1)))
    for affected in vuln.get("affected", []):
        for sev_obj in affected.get("severity", []):
            stype = sev_obj.get("type", "")
            score_str = sev_obj.get("score", "")
            if "CVSS" in stype and score_str:
                try:
                    score = float(score_str)
                    return _cvss_to_severity(score)
                except (ValueError, TypeError):
                    m = re.search(r"(\d+\.?\d*)", str(score_str))
                    if m:
                        return _cvss_to_severity(float(m.group(1)))
        for db in ("ecosystem_specific", "database_specific"):
            sev = (affected.get(db) or {}).get("severity")
            if sev:
                return SEVERITY_MAP.get(str(sev).upper(), "Unknown")
    if "database_specific" in vuln:
        sev = vuln["database_specific"].get("severity")
        if sev:
            return SEVERITY_MAP.get(str(sev).upper(), "Unknown")
    return "Unknown"


def _extract_fixed_version(vuln: Dict, ecosystem: str) -> Optional[str]:
    """Extract fixed version from OSV vuln ranges."""
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("ecosystem") != ecosystem:
            continue
        for r in affected.get("ranges", []):
            for e in r.get("events", []):
                if "fixed" in e:
                    return e["fixed"]
        vers = affected.get("versions")
        if vers:
            return vers[-1]
    return None


def _get_vuln_url(vuln_id: str, references: List[Dict]) -> str:
    """Return best advisory URL for the vulnerability."""
    if not vuln_id:
        return ""
    vid = str(vuln_id).upper()
    if vid.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    if vid.startswith("GHSA-"):
        return f"https://github.com/advisories/{vuln_id}"
    for r in (references or []):
        url = r.get("url", "")
        if url and ("nvd.nist" in url or "github.com/advisories" in url or "osv.dev" in url):
            return url
    return f"https://osv.dev/vulnerability/{vuln_id}"


def _build_remediation_tips(vuln: Dict, severity: str, package: str, fixed_in: Optional[str], ecosystem: str) -> List[str]:
    """Build user-facing remediation tips for a vulnerability."""
    tips = list(SEVERITY_TIPS.get(severity, SEVERITY_TIPS["Unknown"]))
    summary = (vuln.get("summary") or vuln.get("details") or "").lower()
    for kw, tip in VULN_TYPE_TIPS.items():
        if kw in summary:
            tips.append(tip)
    if fixed_in:
        if ecosystem == "PyPI":
            tips.insert(0, f"Run: pip install {package}=={fixed_in} (or add to requirements.txt)")
        elif ecosystem == "npm":
            tips.insert(0, f"Run: npm install {package}@{fixed_in} (or update package.json)")
        elif ecosystem == "RubyGems":
            tips.insert(0, f"Run: bundle update {package} (or set version in Gemfile)")
        elif ecosystem == "Go":
            tips.insert(0, f"Run: go get {package}@{fixed_in}")
        elif ecosystem == "crates.io":
            tips.insert(0, f"Update Cargo.toml: {package} = \"{fixed_in}\"")
    tips.append("Check NVD/CVE advisory for full details and exploitability.")
    return tips


def _build_cyclonedx_bom(deps: List[Dict[str, str]], filename: str) -> Tuple[Bom, List[Dict[str, Any]]]:
    """Build CycloneDX BOM from parsed deps. Returns (Bom, components_list)."""
    bom = Bom()
    bom.metadata = BomMetaData(
        tools=[
            Tool(name="CycloneDX", version="1.6"),
            Tool(name="cyclonedx-python-lib", version="11.6.0"),
        ],
        component=Component(type=ComponentType.FILE, name=filename, bom_ref=f"file:{filename}"),
    )
    components_list = []
    for dep in deps:
        name, version, eco = dep["name"], dep["version"], dep["ecosystem"]
        eco_lower = (eco or "").lower()
        purl_str = f"pkg:{eco_lower}/{name}@{version}" if eco else f"pkg:{name}@{version}"
        bom_ref = purl_str
        purl_type = {"pypi": "pypi", "npm": "npm", "rubygems": "rubygems", "go": "golang", "crates.io": "cargo"}.get(eco_lower, "generic")
        try:
            purl = PackageURL(type=purl_type, name=name, version=version)
        except Exception:
            purl = None
        comp = Component(
            type=ComponentType.LIBRARY,
            name=name,
            version=version,
            bom_ref=bom_ref,
            purl=purl,
        )
        bom.components.add(comp)
        components_list.append({
            "bom_ref": bom_ref,
            "name": name,
            "version": version,
            "type": "library",
            "ecosystem": eco or "",
            "purl": purl_str,
            "cpe": "",
        })
    # Register root component with dependencies so the dependency graph is complete (avoids CycloneDX UserWarning)
    root = bom.metadata.component
    if root and bom.components:
        bom.register_dependency(target=root, depends_on=list(bom.components))
    return bom, components_list


def analyze_dependency_file(file_path: Path, filename: str) -> Dict[str, Any]:
    """
    Analyze uploaded dependency file: parse deps, build CycloneDX BOM, query OSV for vulns, return full report.
    SBOM format: CycloneDX. Vulnerability data: OSV API.
    """
    content = file_path.read_text(encoding="utf-8", errors="replace")
    deps, ecosystem = parse_dependency_file(filename, content)
    if not deps:
        return {
            "filename": filename,
            "ecosystem": ecosystem,
            "components": [],
            "vulnerabilities": [],
            "total_components": 0,
            "total_vulnerabilities": 0,
            "dependencies_scanned": 0,
            "vulnerable_packages_count": 0,
            "component_scan_status": [],
            "severity_distribution": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0},
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "scanner": "CycloneDX",
            "vuln_source": "OSV",
            "error": "No dependencies parsed. Check file format.",
        }

    # Build CycloneDX BOM (not Syft)
    if CYCLONEDX_AVAILABLE:
        bom, components = _build_cyclonedx_bom(deps, filename)
        cyclonedx_json = JsonV1Dot6(bom=bom).output_as_string()
    else:
        components = []
        cyclonedx_json = None
        for dep in deps:
            name, version, eco = dep["name"], dep["version"], dep["ecosystem"]
            purl = f"pkg:{(eco or '').lower()}/{name}@{version}" if eco else f"pkg:{name}@{version}"
            components.append({
                "bom_ref": purl,
                "name": name,
                "version": version,
                "type": "library",
                "ecosystem": eco or "",
                "purl": purl,
                "cpe": "",
            })

    all_vulns = []
    severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    packages_skipped_unknown_version = []
    # Severity order for "max" (highest first)
    SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Unknown")

    for dep in deps:
        name, version, eco = dep["name"], dep["version"], dep["ecosystem"]
        # Skip vulnerability scan for unknown version (per spec: skip or warn)
        if (version or "").lower() == "unknown" or not (version or "").strip():
            packages_skipped_unknown_version.append(name)
            continue
        vulns_raw = query_osv(name, version, eco)
        for v in vulns_raw:
            severity = _extract_severity(v)
            fixed_in = _extract_fixed_version(v, eco)
            tips = _build_remediation_tips(v, severity, name, fixed_in, eco)
            refs = v.get("references", [])
            vuln_obj = {
                "id": v.get("id", "Unknown"),
                "package": name,
                "version": version,
                "severity": severity,
                "description": v.get("summary") or v.get("details", "")[:500],
                "fixed_in": fixed_in or "Not specified",
                "tips": tips,
                "references": [r.get("url", "") for r in refs if r.get("url")][:5],
                "url": _get_vuln_url(v.get("id", ""), refs),
            }
            all_vulns.append(vuln_obj)
            severity_count[severity] = severity_count.get(severity, 0) + 1

    # Unique packages (name, version) that have at least one vulnerability
    vulnerable_package_keys = set((v["package"], v["version"]) for v in all_vulns)
    vulnerable_packages_count = len(vulnerable_package_keys)

    # Vulns per package for scan status (package_key -> list of vulns)
    vulns_by_package: Dict[tuple, List[Dict]] = {}
    for v in all_vulns:
        key = (v["package"], v["version"])
        vulns_by_package.setdefault(key, []).append(v)

    def max_severity(vuln_list: List[Dict]) -> str:
        for sev in SEVERITY_ORDER:
            if any(v.get("severity") == sev for v in vuln_list):
                return sev
        return "Unknown"

    # Per-package scan status: scanned, vulnerable, max_severity, vuln_count
    component_scan_status: List[Dict[str, Any]] = []
    for dep in deps:
        name, version, eco = dep["name"], dep["version"], dep["ecosystem"]
        scanned = (version or "").lower() != "unknown" and bool((version or "").strip())
        key = (name, version)
        pkg_vulns = vulns_by_package.get(key, [])
        vulnerable = len(pkg_vulns) > 0
        component_scan_status.append({
            "name": name,
            "version": version,
            "ecosystem": eco or "",
            "scanned": scanned,
            "vulnerable": vulnerable,
            "vuln_count": len(pkg_vulns),
            "max_severity": max_severity(pkg_vulns) if pkg_vulns else None,
        })

    dependencies_scanned = len(deps) - len(packages_skipped_unknown_version)

    result = {
        "filename": filename,
        "ecosystem": ecosystem,
        "components": components,
        "vulnerabilities": all_vulns,
        "total_components": len(components),
        "total_vulnerabilities": len(all_vulns),
        "dependencies_scanned": dependencies_scanned,
        "vulnerable_packages_count": vulnerable_packages_count,
        "component_scan_status": component_scan_status,
        "severity_distribution": severity_count,
        "scan_timestamp": datetime.utcnow().isoformat() + "Z",
        "scanner": "CycloneDX",
        "vuln_source": "OSV",
        "cyclonedx_bom_json": cyclonedx_json,
    }
    if packages_skipped_unknown_version:
        result["warnings"] = [
            f"Skipped vulnerability scan for {len(packages_skipped_unknown_version)} package(s) with unknown version: {', '.join(packages_skipped_unknown_version[:10])}"
            + ("..." if len(packages_skipped_unknown_version) > 10 else ""),
        ]
    return result
