"""
Network Traffic Classification & Anomaly Detection - FastAPI Backend
"""
import os
import json
import uuid
import random
import glob
from datetime import datetime, timedelta
from pathlib import Path
import shutil
from app.services.decision_service import decision_engine
from app import db

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any, Tuple

app = FastAPI(
    title="Network Security Intelligence API",
    description="Hybrid ML-based network security intelligence system",
    version="1.0.0",
)

# CORS - allow frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
db.init_db()

# ── In-memory storage (for analysis results only) ────────────────────
# Flow records are now stored in SQLite database (db.py)
analysis_results: Dict[str, Any] = {}

# ── Simulated model metrics (Replace with real metrics if available) ──────
# Ideally load metrics.json from training artifacts
MODEL_METRICS = {
    "random_forest": {
        "name": "Random Forest",
        "accuracy": 0.964,
        "precision": 0.958,
        "recall": 0.951,
        "f1_score": 0.954,
        "confusion_matrix": [
            [4521, 87, 32, 15],
            [62, 3892, 45, 22],
            [28, 51, 2145, 18],
            [12, 19, 25, 1876],
        ],
        "roc_auc": 0.987,
        "classes": ["Benign", "DDoS", "PortScan", "BruteForce"],
    },
    "xgboost": {
        "name": "XGBoost",
        "accuracy": 0.971,
        "precision": 0.965,
        "recall": 0.962,
        "f1_score": 0.963,
        "confusion_matrix": [
            [4580, 45, 22, 8],
            [38, 3950, 25, 8],
            [15, 30, 2180, 17],
            [8, 12, 15, 1897],
        ],
        "roc_auc": 0.992,
        "classes": ["Benign", "DDoS", "PortScan", "BruteForce"],
    },
    "isolation_forest": {
        "name": "Isolation Forest (Anomaly)",
        "accuracy": 0.928,
        "precision": 0.915,
        "recall": 0.932,
        "f1_score": 0.923,
        "confusion_matrix": [
            [8950, 450],
            [320, 4280],
        ],
        "roc_auc": 0.961,
        "classes": ["Normal", "Anomaly"],
    },
}

# ── Attack types and their weights ──────────────────────────────────────
ATTACK_TYPES = {
    "Benign": 0.55,
    "DDoS": 0.15,
    "PortScan": 0.10,
    "BruteForce": 0.07,
    "Web Attack": 0.05,
    "Bot": 0.04,
    "Infiltration": 0.02,
    "Heartbleed": 0.02,
}


def generate_demo_flows(count: int = 200) -> List[Dict[str, Any]]:
    """Generate realistic-looking flow records for demonstration (Fallback)."""
    protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH"]
    src_ips = [
        "192.168.1." + str(i) for i in range(10, 60)
    ] + [
        "10.0.0." + str(i) for i in range(1, 30)
    ]
    dst_ips = [
        "172.16.0." + str(i) for i in range(1, 20)
    ] + [
        "8.8.8.8", "1.1.1.1", "204.79.197.200", "142.250.190.46",
    ]

    flows = []
    types_list = list(ATTACK_TYPES.keys())
    weights = list(ATTACK_TYPES.values())

    for i in range(count):
        attack_type = random.choices(types_list, weights=weights, k=1)[0]
        is_anomaly = attack_type != "Benign"
        anomaly_score = round(random.uniform(0.7, 0.99), 3) if is_anomaly else round(random.uniform(0.01, 0.3), 3)
        confidence = round(random.uniform(0.75, 0.99), 3)
        risk_score = round(
            (anomaly_score * 0.4 + (1 - confidence if is_anomaly else 0) * 0.2 + (0.8 if is_anomaly else 0.1) * 0.4),
            3,
        )

        flow = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(0, 1440))).isoformat(),
            "src_ip": random.choice(src_ips),
            "dst_ip": random.choice(dst_ips),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 22, 53, 8080, 3389, 445, 25, 110]),
            "protocol": random.choice(protocols),
            "duration": round(random.uniform(0.001, 120.0), 3),
            "total_fwd_packets": random.randint(1, 500),
            "total_bwd_packets": random.randint(0, 400),
            "total_length_fwd": random.randint(40, 150000),
            "total_length_bwd": random.randint(0, 120000),
            "flow_bytes_per_sec": round(random.uniform(100, 500000), 2),
            "flow_packets_per_sec": round(random.uniform(1, 5000), 2),
            "classification": attack_type,
            "confidence": confidence,
            "anomaly_score": anomaly_score,
            "risk_score": risk_score,
            "is_anomaly": is_anomaly,
            "risk_level": "Critical" if risk_score > 0.7 else "High" if risk_score > 0.5 else "Medium" if risk_score > 0.3 else "Low",
        }
        flows.append(flow)

    return flows

def load_real_data_sample(limit: int = 500) -> List[Dict[str, Any]]:
    """Load a sample of real data from processed folder, or raw/cic_ids (e.g. after synthetic generation)."""
    project_root = Path(__file__).parent.parent.parent
    processed_path = project_root / "training_pipeline" / "data" / "processed" / "cic_ids" / "flows"
    raw_path = project_root / "training_pipeline" / "data" / "raw" / "cic_ids"
    
    csv_files = list(processed_path.rglob("*.csv")) if processed_path.exists() else []
    if not csv_files and raw_path.exists():
        csv_files = list(raw_path.glob("*.csv"))
    
    if not csv_files:
        print("No real data files found. Using demo data.")
        return generate_demo_flows(limit)
    
    # Use the first available file
    target_file = csv_files[0]
    print(f"Loading initial dashboard data from: {target_file}")
    
    try:
        # Analyze file using our ML engine
        result = decision_engine.analyze_file(str(target_file), "csv")
        if "flows" in result:
            flows = result["flows"]
            # Add timestamps incrementally to simulate timeline (since raw data might not have absolute time)
            base_time = datetime.now()
            for i, flow in enumerate(flows):
                flow["timestamp"] = (base_time - timedelta(minutes=i)).isoformat()
            
            return flows[:limit]
    except Exception as e:
        print(f"Error loading real data: {e}. Using demo data.")
        
    return generate_demo_flows(limit)


# ── Initialize Data ─────────────────────────────────────────────────────
# Start with empty records - data will be populated when users upload files
# To test with demo data, uncomment the line below:
# flow_records = load_real_data_sample(500)


# ── Pydantic Models ─────────────────────────────────────────────────────
class AnalysisResult(BaseModel):
    id: str
    filename: str
    timestamp: str
    total_flows: int
    attack_distribution: Dict[str, int]
    anomaly_count: int
    avg_risk_score: float


# ── Health Check ────────────────────────────────────────────────────────
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "models_loaded": True,
        "services": {
            "supervised_model": "active" if decision_engine.rf_model else "inactive (no labels)",
            "anomaly_detector": "active" if decision_engine.if_model else "inactive",
            "decision_engine": "active",
            "sbom_scanner": "active",
        },
    }


# ── Dashboard Stats ─────────────────────────────────────────────────────
@app.get("/api/dashboard/stats")
async def dashboard_stats():
    """Get dashboard statistics from database."""
    return db.get_dashboard_stats()


# ── Traffic Flows ────────────────────────────────────────────────────────
@app.get("/api/traffic/flows")
async def get_flows(
    page: int = 1,
    per_page: int = 20,
    classification: Optional[str] = None,
    risk_level: Optional[str] = None,
    src_ip: Optional[str] = None,
    protocol: Optional[str] = None,
):
    flows, total = db.get_flows(
        page=page,
        per_page=per_page,
        classification=classification,
        risk_level=risk_level,
        src_ip=src_ip,
        protocol=protocol,
    )
    
    return {
        "flows": flows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
    }


@app.get("/api/traffic/trends")
async def get_traffic_trends(
    classification: Optional[str] = None,
    risk_level: Optional[str] = None,
    src_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    points: int = 72,
):
    return db.get_traffic_trends(
        classification=classification,
        risk_level=risk_level,
        src_ip=src_ip,
        protocol=protocol,
        points=points,
    )


@app.get("/api/upload/{analysis_id}/flows")
async def get_upload_flows(
    analysis_id: str,
    page: int = 1,
    per_page: int = 200,
):
    """Get paginated flows for one uploaded file analysis."""
    per_page = max(1, min(per_page, 1000))
    flows, total = db.get_flows(
        page=page,
        per_page=per_page,
        analysis_id=analysis_id,
    )
    return {
        "analysis_id": analysis_id,
        "flows": flows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
        "has_more": (page * per_page) < total,
    }


# ── Anomalies ───────────────────────────────────────────────────────────
@app.get("/api/anomalies")
async def get_anomalies(
    page: int = 1,
    per_page: int = 20,
    classification: Optional[str] = None,
    risk_level: Optional[str] = None,
    src_ip: Optional[str] = None,
    protocol: Optional[str] = None,
):
    """Get threat data (all attack/anomaly types) from uploaded flow records in database."""
    per_page = max(1, min(per_page, 200))
    return db.get_threat_data(
        page=page,
        per_page=per_page,
        classification=classification,
        risk_level=risk_level,
        src_ip=src_ip,
        protocol=protocol,
    )


# ── Model Performance ────────────────────────────────────────────────────
def _load_training_metrics() -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    """Load metrics from training_pipeline/models/metrics.json if present."""
    metrics_path = Path(__file__).parent.parent.parent / "training_pipeline" / "models" / "metrics.json"
    if metrics_path.exists():
        try:
            with open(metrics_path, "r") as f:
                data = json.load(f)
            models = data.get("models", {}) or {}
            training_info = data.get("training_info", {})
            return models, training_info, "metrics_json"
        except Exception as e:
            print(f"Could not load metrics.json: {e}")
    return {}, {}, "runtime_only"


@app.get("/api/models/metrics")
async def model_metrics():
    models, training_info, source = _load_training_metrics()
    dashboard = db.get_dashboard_stats()

    total_flows = dashboard.get("total_flows", 0) or 0
    total_anomalies = dashboard.get("total_anomalies", 0) or 0
    avg_risk_score = dashboard.get("avg_risk_score", 0) or 0

    # Runtime metrics from actual uploaded/analyzed flow data.
    recent_flows, _ = db.get_flows(page=1, per_page=1000)
    avg_conf = (
        float(sum(f.get("confidence", 0) for f in recent_flows) / max(len(recent_flows), 1))
        if total_flows > 0 else 0.0
    )

    live_metrics = {
        "total_flows": total_flows,
        "total_anomalies": total_anomalies,
        "anomaly_rate": round((total_anomalies / max(total_flows, 1)) * 100, 2),
        "avg_risk_score": avg_risk_score,
        "avg_confidence": round(avg_conf, 4),
        "risk_distribution": dashboard.get("risk_distribution", {}),
    }

    if not training_info:
        training_info = {
            "dataset": "Runtime uploaded flows",
            "total_samples": total_flows,
            "training_samples": 0,
            "test_samples": 0,
            "feature_count": len(decision_engine.feature_names) if decision_engine.feature_names is not None else 0,
            "last_trained": None,
        }

    return {
        "models": models,
        "training_info": training_info,
        "live_metrics": live_metrics,
        "model_status": {
            "supervised_loaded": bool(decision_engine.rf_model and decision_engine.label_encoder),
            "unsupervised_loaded": bool(decision_engine.if_model),
            "scaler_loaded": bool(decision_engine.scaler),
        },
        "source": source,
    }


# ── File Upload ──────────────────────────────────────────────────────────
@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    global flow_records, analysis_results
    
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    allowed = (".pcap", ".pcapng", ".csv")
    if not any(file.filename.lower().endswith(ext) for ext in allowed):
        raise HTTPException(
            status_code=400,
            detail=f"File type not supported. Allowed: {', '.join(allowed)}",
        )

    # Save to temp file
    temp_dir = Path(__file__).parent.parent.parent.parent / "temp_uploads"
    temp_dir.mkdir(exist_ok=True)
    
    file_path = temp_dir / f"{uuid.uuid4()}_{file.filename}"
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
        
    try:
        # Run real analysis
        ext = file.filename.split('.')[-1].lower()
        if ext == 'pcapng': ext = 'pcap'
        
        result = decision_engine.analyze_file(
            str(file_path),
            ext,
            include_flows=False,
            source_filename=file.filename,
            on_chunk_processed=db.insert_flows
        )
        
        if "error" in result:
             raise HTTPException(status_code=500, detail=result["error"])

        analysis_results[result['id']] = result
        
        return {
            "status": "success",
            "id": result['id'],
            "filename": file.filename,
            "total_flows": result.get('total_flows', 0),
            "attack_distribution": result.get('attack_distribution', {}),
            "risk_distribution": result.get('risk_distribution', {}),
            "anomaly_count": result.get('anomaly_count', 0),
            "avg_risk_score": result.get('avg_risk_score', 0),
            "sample_flows": result.get('sample_flows', []),
            "report_details": result.get('report_details', {}),
            "file_size": file.size if hasattr(file, "size") and file.size is not None else None,
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if file_path.exists():
            try:
                os.remove(file_path)
            except:
                pass


# ── SBOM Security ────────────────────────────────────────────────────────
def _resolve_sbom_path() -> Path:
    """Resolve SBOM file path from known locations."""
    possible_paths = [
        Path(__file__).parent.parent.parent.parent / "security" / "sbom.json",
        Path("/home/ictd/Desktop/Network/nal/security/sbom.json"),
        Path("../../security/sbom.json"),
    ]
    for p in possible_paths:
        if p.exists():
            return p
    raise HTTPException(
        status_code=404,
        detail=f"SBOM file not found. Searched: {[str(p) for p in possible_paths]}"
    )


@app.get("/api/security/sbom")
async def get_sbom():
    """Get SBOM data."""
    sbom_path = _resolve_sbom_path()

    with open(sbom_path, "r") as f:
        sbom_data = json.load(f)

    components = sbom_data.get("components", [])
    metadata = sbom_data.get("metadata", {}) or {}
    tools = metadata.get("tools", {}) or {}
    tool_components = tools.get("components", []) if isinstance(tools, dict) else []
    metadata_component = metadata.get("component", {}) or {}

    return {
        "schema": sbom_data.get("$schema"),
        "format": sbom_data.get("bomFormat", "CycloneDX"),
        "spec_version": sbom_data.get("specVersion", "unknown"),
        "serial_number": sbom_data.get("serialNumber"),
        "document_version": sbom_data.get("version"),
        "total_components": len(components),
        "metadata": {
            "timestamp": metadata.get("timestamp"),
            "component": {
                "bom_ref": metadata_component.get("bom-ref"),
                "type": metadata_component.get("type"),
                "name": metadata_component.get("name"),
                "version": metadata_component.get("version"),
            },
            "tools": [
                {
                    "type": t.get("type"),
                    "author": t.get("author"),
                    "name": t.get("name"),
                    "version": t.get("version"),
                }
                for t in tool_components
            ]
        },
        "components": [
            {
                "bom_ref": c.get("bom-ref"),
                "name": c.get("name", "unknown"),
                "version": c.get("version", "unknown"),
                "type": c.get("type", "library"),
                "purl": c.get("purl", ""),
                "cpe": c.get("cpe", ""),
                "properties": c.get("properties", []),
            }
            for c in components
        ],
    }


@app.get("/api/security/vulnerabilities")
async def get_vulnerabilities():
    """Simulated vulnerability scan results."""
    vulns = [
        {"id": "CVE-2024-3651", "package": "idna", "version": "3.6", "severity": "High",
         "description": "Denial of service via resource consumption", "fixed_in": "3.7"},
        {"id": "CVE-2024-35195", "package": "requests", "version": "2.31.0", "severity": "Medium",
         "description": "Session cookie handling vulnerability", "fixed_in": "2.32.0"},
        {"id": "CVE-2023-45803", "package": "urllib3", "version": "2.0.7", "severity": "Medium",
         "description": "Request body not stripped after redirect", "fixed_in": "2.1.0"},
        {"id": "CVE-2024-0727", "package": "cryptography", "version": "41.0.7", "severity": "Low",
         "description": "NULL dereference processing PKCS12", "fixed_in": "42.0.0"},
        {"id": "CVE-2023-50447", "package": "Pillow", "version": "10.1.0", "severity": "Critical",
         "description": "Arbitrary code execution via crafted image", "fixed_in": "10.2.0"},
        {"id": "CVE-2024-22195", "package": "Jinja2", "version": "3.1.2", "severity": "Medium",
         "description": "Cross-site scripting in xmlattr filter", "fixed_in": "3.1.3"},
    ]

    severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for v in vulns:
        severity_count[v["severity"]] += 1

    return {
        "total_vulnerabilities": len(vulns),
        "severity_distribution": severity_count,
        "vulnerabilities": vulns,
        "scan_timestamp": datetime.now().isoformat(),
        "scanner": "Grype",
    }


@app.get("/api/security/sbom/download")
async def download_sbom():
    """Download SBOM file as JSON."""
    sbom_path = _resolve_sbom_path()
    
    return FileResponse(
        path=str(sbom_path),
        filename="sbom.json",
        media_type="application/json",
    )


# ── Root ─────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "message": "Network Security Intelligence API",
        "docs": "/docs",
        "version": "1.0.0",
    }
