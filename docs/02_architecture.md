# System Architecture

## Architecture Summary

The project is a multi-component security analytics stack:

- `nal/backend`: FastAPI service exposing all APIs and orchestrating ML inference.
- `nal/core`: shared feature preprocessing functions used by training/inference.
- `nal/training_pipeline`: artifact generation for Random Forest, Isolation Forest, scaler, and metadata.
- `nal/frontend`: React/Vite dashboard consuming backend APIs.
- `nal/n8n`: automation workflows for monitoring, alerting, reporting, and control.
- Root runtime storage: `flows.db` SQLite database and temporary upload/processing folders.

## Component Responsibilities

### 1) Backend API and Orchestration
- Entry point: `nal/backend/app/main.py`.
- Exposes endpoints for health, traffic, anomalies, history, uploads, realtime, model metrics, and SBOM.
- Delegates inference to `decision_service`, live capture to `realtime_service`, storage to `db.py`, and dependency scanning to `sbom_service`.

### 2) Decision Engine
- File: `nal/backend/app/services/decision_service.py`.
- Loads artifacts from `nal/training_pipeline/models`.
- Converts PCAP/PCAPNG to CSV via `cicflowmeter` if needed.
- Cleans/aligned features, applies scaler/model inference, computes risk, threat type, CVE context, and explanatory text.

### 3) Data Persistence
- File: `nal/backend/app/db.py`.
- SQLite schema:
  - `flows` table: per-flow telemetry and inferred security context.
  - `analysis_history` table: per-analysis metadata.
- Implements filtering, pagination, trend aggregation, and monitor-type partitioning (`passive` vs `active`).

### 4) Realtime Capture
- File: `nal/backend/app/services/realtime_service.py`.
- Scapy packet sniffing loop in background thread.
- Packet-to-flow aggregation computes CIC-like feature set.
- Reuses same decision logic (`classify_flows`) as passive path.

### 5) ML Training Pipeline
- Files: `nal/training_pipeline/train.py`, `nal/core/feature_engineering.py`, scripts under `nal/training_pipeline/scripts`.
- Trains:
  - `RandomForestClassifier` (supervised),
  - `IsolationForest` (unsupervised).
- Saves: models, scaler, label encoder, feature names, and `metrics.json`.

### 6) Frontend
- File roots: `nal/frontend/src`.
- Routing in `App.jsx`; API client in `src/services/api.js`.
- Pages for dashboard, upload, active monitoring, anomalies, history/reporting, traffic analysis, model metrics, and SBOM security.

### 7) n8n Automation
- JSON workflows in `nal/n8n`.
- Automates:
  - periodic health/risk checks,
  - scheduled/on-demand file analysis,
  - model/training status reporting,
  - daily report generation,
  - live-monitor control and health polling.

## Architecture Diagram

```mermaid
flowchart LR
  U1[PCAP/CSV Upload] --> B[FastAPI Backend]
  U2[Live Packets via Interface] --> R[Realtime Monitor Service]
  R --> D
  B --> D[Decision Engine]
  D --> M1[Random Forest]
  D --> M2[Isolation Forest]
  D --> C[Threat/CVE Mapping + Risk Scoring]
  C --> DB[(SQLite flows.db)]
  DB --> API[Query APIs]
  API --> FE[React Dashboard]
  API --> N8N[n8n Workflows]
  TP[Training Pipeline] --> ART[Model Artifacts]
  ART --> D
  SB[SBOM Upload] --> B
  B --> OSV[OSV API]
```

## Tech Stack by Component

- Backend/API: FastAPI, Uvicorn, Pydantic, SQLite (`sqlite3`), Pandas, NumPy.
- ML: scikit-learn (RandomForest, IsolationForest), StandardScaler, LabelEncoder, joblib/pickle artifacts.
- Packet and flow handling: Scapy + CICFlowMeter.
- Frontend: React 18, Vite, Axios, Chart.js, TailwindCSS.
- SBOM/security: cyclonedx-python-lib, OSV API, dependency parser utilities.
- Automation: n8n workflows and webhook/HTTP integrations.
- Containerization: Docker + docker-compose for backend/frontend/n8n services.
