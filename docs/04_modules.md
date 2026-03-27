# Module Breakdown

## Backend API Module (`nal/backend/app/main.py`)

- **Purpose:** Central HTTP interface and orchestration layer.
- **Key Inputs:** file uploads, query parameters, realtime control commands, SBOM files.
- **Key Outputs:** JSON responses for UI/n8n; persistent DB writes via `db.py`.
- **Dependencies:** FastAPI, `decision_service`, `realtime_service`, `sbom_service`, `db.py`.
- **Internal Working:** initializes DB at startup, defines all routes, validates uploads, and maps each route to service/database operations.

## Database Module (`nal/backend/app/db.py`)

- **Purpose:** Persistent storage and aggregated querying over flow/security telemetry.
- **Key Files:** `flows.db` (root), schema logic in `init_db()`.
- **Inputs:** enriched flow dictionaries from passive/active processing.
- **Outputs:** paginated rows, dashboard aggregates, trend points, analysis reports.
- **Dependencies:** `sqlite3`, thread lock for safe concurrent access.

## Decision Module (`nal/backend/app/services/decision_service.py`)

- **Purpose:** ML inference pipeline for uploaded files and realtime flow batches.
- **Inputs:** CSV rows or raw flow feature dicts.
- **Outputs:** per-flow `classification`, `confidence`, `anomaly_score`, `risk_score`, `risk_level`, `threat_type`, `cve_refs`.
- **Dependencies:** model artifacts from `training_pipeline/models`, `core.feature_engineering`, `classification_config`.
- **Internal Working:** loads artifacts once, optionally converts PCAP to CSV, processes in chunks, computes hybrid scoring, and returns report structures.

## Realtime Monitoring Module (`nal/backend/app/services/realtime_service.py`)

- **Purpose:** Active packet capture and near-real-time flow inference.
- **Inputs:** network packets from selected interface using Scapy.
- **Outputs:** active-mode flow records inserted to DB.
- **Dependencies:** Scapy, `decision_service.classify_flows`, `db.insert_flows`.
- **Internal Working:** capture loop (5s windows), packet grouping by normalized 5-tuple, CIC-like feature aggregation, classification, DB insertion.

## Classification Rules Module (`nal/backend/app/classification_config.py`)

- **Purpose:** Rule and threshold authority for risk mapping and threat/CVE semantics.
- **Inputs:** flow-derived risk score, anomaly score, feature behavior.
- **Outputs:** risk levels, inferred unsupervised threat labels, explanatory strings.
- **Dependencies:** consumed primarily by `decision_service`.

## SBOM Security Module (`nal/backend/app/services/sbom_service.py`)

- **Purpose:** Dependency file parsing, CycloneDX generation, OSV vulnerability lookup.
- **Inputs:** uploaded manifests (`requirements.txt`, `package.json`, lock files, etc.).
- **Outputs:** components list, vulnerabilities, severity distribution, remediation tips.
- **Dependencies:** `cyclonedx-python-lib` (if available), `requests` (OSV API), regex/json parsers.

## Shared Feature Engineering Module (`nal/core/feature_engineering.py`)

- **Purpose:** data cleaning and preprocessing for training/inference consistency.
- **Inputs:** raw flow DataFrame.
- **Outputs:** scaled numeric matrix, optional encoded labels, scaler/encoder artifacts.
- **Dependencies:** NumPy, Pandas, scikit-learn preprocessing.

## Training Orchestration Module (`nal/training_pipeline/train.py`)

- **Purpose:** Train supervised and unsupervised models, save artifacts/metrics.
- **Inputs:** CSV files under processed flow datasets (recursive).
- **Outputs:** `rf_model.pkl`, `if_model.pkl`, scaler/encoder/features, `metrics.json`.
- **Dependencies:** `core.feature_engineering`, scikit-learn estimators.

## Training Support Scripts (`nal/training_pipeline/scripts`)

- `generate_synthetic_data.py`: fallback synthetic CIC-like dataset generation.
- `generate_doomsday_flows.py`: synthetic processed-flow generator with attack/severity variation.
- `pcap_chunks_to_flows.py`: batch conversion from pcap chunks to CSV via CICFlowMeter.
- `setup_project.py`: legacy setup helper referencing path config module (currently not aligned with present tree).

## Frontend Module (`nal/frontend/src`)

- **Purpose:** visualization and operator control plane.
- **Key Files:** `App.jsx`, `services/api.js`, page components.
- **Inputs:** backend APIs and user interaction.
- **Outputs:** dashboards, triage tables, report views, monitor controls, SBOM UI.
- **Dependencies:** React, Axios, Chart.js, react-router, Tailwind.

## Automation Module (`nal/n8n`)

- **Purpose:** no-code orchestration for periodic checks, alerts, reports, and control hooks.
- **Key Files:** five workflow JSON definitions + `import_workflows.sh`.
- **Inputs:** scheduled triggers/webhooks + backend API responses.
- **Outputs:** webhook/Slack notifications, monitor/start-stop actions, report payloads.
