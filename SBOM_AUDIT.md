# SBOM Implementation Audit

Checklist against the **Stable Version** requirements (MUST vs SHOULD).

---

## 1. Secure File Upload System

| Requirement | Status | Notes |
|-------------|--------|--------|
| Accept only supported dependency files | ✅ | Backend: `.txt`, `.json`, Pipfile, poetry.lock, Gemfile, Gemfile.lock, go.mod, Cargo.toml, Cargo.lock, package-lock.json, yarn.lock. Frontend `accept` and `ALLOWED_FILES` aligned. |
| Validate file type and size | ⚠️→✅ | Type validated. **Size limit added**: max 5 MB for SBOM analyze. |
| Do NOT store permanently (process → discard) | ✅ | File written to temp, analyzed, then `file_path.unlink()` in `finally`. Only in-memory `_user_sbom_result` kept. |
| Project's own dependencies never scanned | ✅ | No static project deps; only user-uploaded file content is parsed. |

---

## 2. Ecosystem-Specific Parsers

| Ecosystem | Required | Status | Notes |
|-----------|----------|--------|--------|
| PyPI | package==version, comments | ✅ | `_parse_requirements_txt`: regex for `name op version`, strip `#` comments. Pipfile, poetry.lock. |
| npm | dependencies + devDependencies | ✅ | `_parse_package_json`: dependencies, devDependencies, peerDependencies. |
| Lock files | Exact resolved versions | ✅ | package-lock.json, yarn.lock, poetry.lock, Gemfile.lock, Cargo.lock use resolved/exact versions. |
| Go | require block | ✅ | `_parse_gomod`: require ( ) block. |
| Cargo | [dependencies] | ✅ | `_parse_cargo_toml`, `_parse_cargo_lock`. |

Parser output shape: `{ "name", "version", "ecosystem" }` ✅ (plus optional "unknown" version handling).

---

## 3. Version Normalization Layer

| Requirement | Status | Notes |
|-------------|--------|--------|
| Handle >=, ^, ~ | ⚠️→✅ | requirements.txt: version string kept as-is for OSV (OSV accepts ranges). package.json: strip ^/~ and take first digit part; **missing version → "unknown"**. |
| No version specified | ⚠️→✅ | **Implemented**: version "unknown"; vulnerability scan skipped for that package; user warning in report. |
| Editable installs | ⚠️→✅ | requirements.txt: lines starting with `-e` or `-e ` skipped (not parsed as package). |
| Git installs | ⚠️→✅ | requirements.txt: lines with `git+`, `hg+`, `svn+`, `bzr+` or `file://` skipped (version "unknown" if ever parsed). |

---

## 4. Internal SBOM Builder

| Requirement | Status | Notes |
|-------------|--------|--------|
| Internal SBOM model before vulnerability query | ✅ | `analyze_dependency_file`: parse → build components (with purl) → then query OSV. |
| Structure with name, version, ecosystem, purl | ✅ | `_build_cyclonedx_bom` / fallback build `components` with name, version, type, purl. |
| Package URL (purl) format | ✅ | `pkg:{ecosystem}/{name}@{version}`; PackageURL used when cyclonedx available. |

---

## 5. Vulnerability Query Layer

| Requirement | Status | Notes |
|-------------|--------|--------|
| Use OSV API | ✅ | `query_osv()` POST to `https://api.osv.dev/v1/query`. |
| Query by name + version | ✅ | Payload: package name, ecosystem, version. |
| Pagination | ✅ | `next_page_token` loop until no more pages. |
| Collect ID, Severity, CVSS, Fixed version, References | ✅ | `_extract_severity`, `_extract_fixed_version`, `_get_vuln_url`; vuln object has id, severity, description, fixed_in, references, url. |

---

## 6. Severity Classification Engine

| Requirement | Status | Notes |
|-------------|--------|--------|
| CVSS 9–10 → Critical | ✅ | `_cvss_to_severity`. |
| 7–8.9 → High | ✅ | |
| 4–6.9 → Medium | ✅ | |
| 0.1–3.9 → Low | ✅ | |
| If CVSS missing: use OSV severity label | ✅ | SEVERITY_MAP from OSV/database_specific. |
| Otherwise mark as "Unknown" | ⚠️→✅ | **Fixed**: final fallback is "Unknown" instead of "Medium". |

---

## 7. Remediation Engine

| Requirement | Status | Notes |
|-------------|--------|--------|
| Fixed version | ✅ | `_extract_fixed_version`. |
| Upgrade command | ✅ | `_build_remediation_tips`: ecosystem-specific (pip, npm, bundle, go get, Cargo). |
| Ecosystem-specific advice | ✅ | SEVERITY_TIPS + VULN_TYPE_TIPS + upgrade line. |
| Advisory link (NVD / GHSA / OSV) | ✅ | `_get_vuln_url`: CVE→NVD, GHSA→GitHub Advisories, else OSV. |

---

## 8. Final UI Output

| Requirement | Status | Notes |
|-------------|--------|--------|
| Total dependencies | ✅ | KPI + components table. |
| Total vulnerabilities | ✅ | KPI. |
| Severity breakdown | ✅ | Doughnut + bar, severity_distribution. |
| Per-package vulnerability list | ✅ | vulnerabilities tab with id, package, version, severity, description, fixed_in. |
| Advisory links | ✅ | External link icon → NVD/GHSA/OSV. |
| Remediation tips | ✅ | Expandable tips per vuln. |

---

## Final SBOM Content (Metadata, Components, Vulnerabilities, Summary)

| Section | Status | Notes |
|---------|--------|--------|
| Metadata: SBOM version, timestamp, ecosystem, total components, tool version | ✅ | format CycloneDX, scan_timestamp, ecosystem, total_components, scanner/vuln_source. |
| Components: name, version, ecosystem, PURL | ✅ | components list with name, version, type, purl. |
| Vulnerabilities: ID, package, affected version, severity, CVSS, fixed version, advisory link, summary, remediation | ✅ | Full vuln objects + tips. |
| Summary: total vulns, severity distribution | ✅ | total_vulnerabilities, severity_distribution. |

---

## SHOULD Improve (Optional)

| Item | Status | Notes |
|------|--------|--------|
| Caching: (package_name, version) → OSV response | ❌ | Not implemented. Would reduce latency and rate-limit risk. |
| Lockfile priority: package.json + package-lock.json → use lockfile version | ❌ | Single-file upload only; no automatic pairing. Could add "upload lockfile if present" hint or second optional file. |
| Transitive dependency awareness | ❌ | Only top-level / lockfile-resolved list; no nested tree. Documented as roadmap. |
| SBOM export: CycloneDX + SPDX | ⚠️ | CycloneDX JSON download ✅. SPDX not implemented. |
| Performance: batching, timeout, error fallback | ⚠️ | Timeout 20s per OSV request; no batching; on failure we log and return empty vulns for that package. |

---

## Architecture Flow (Current)

```
User Upload → File Validation (type + size) → Ecosystem Detection → Parser Layer
  → Version Normalization (unknown, skip editable/git)
  → SBOM Component Builder (with purl)
  → Vulnerability Enrichment (OSV API, skip unknown version)
  → Severity Engine (CVSS → else OSV label → else Unknown)
  → Remediation Engine
  → Final Report → UI + CycloneDX Download
```

---

*Last updated: after implementing file size limit, version "unknown" handling, editable/git skip, and severity "Unknown" fallback.*
