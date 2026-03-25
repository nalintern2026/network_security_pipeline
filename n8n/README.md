# NetGuard n8n Automation Workflows

Complete n8n workflow suite for automating the NetGuard Network Security Intelligence system. These workflows connect to the FastAPI backend API to orchestrate monitoring, alerting, training, and reporting.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [How the NetGuard System Works](#how-the-netguard-system-works)
3. [Workflow 1: Security Monitoring & Alerting](#workflow-1-security-monitoring--alerting)
4. [Workflow 2: Automated File Analysis](#workflow-2-automated-file-analysis)
5. [Workflow 3: Training Pipeline Automation](#workflow-3-training-pipeline-automation)
6. [Workflow 4: Daily Security Report](#workflow-4-daily-security-report)
7. [Workflow 5: Live Monitoring Management](#workflow-5-live-monitoring-management)
8. [Setup & Configuration](#setup--configuration)
9. [Environment Variables](#environment-variables)
10. [API Endpoints Reference](#api-endpoints-reference)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          n8n Workflows                              │
│                                                                     │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐               │
│  │  Monitoring   │ │  File        │ │  Training    │               │
│  │  & Alerting   │ │  Analysis    │ │  Pipeline    │               │
│  │  (5 min)      │ │  (webhook/   │ │  (weekly)    │               │
│  │              │ │   10 min)    │ │              │               │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘               │
│         │                │                │                        │
│  ┌──────┴───────┐ ┌──────┴───────┐                                │
│  │  Daily        │ │  Live Monitor│                                │
│  │  Report       │ │  Management  │                                │
│  │  (8 AM)       │ │  (2 min poll)│                                │
│  └──────┬───────┘ └──────┬───────┘                                │
│         │                │                                         │
└─────────┼────────────────┼─────────────────────────────────────────┘
          │                │
          ▼                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    FastAPI Backend (port 8000)                       │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │                   Decision Engine                         │      │
│  │  ┌─────────────┐  ┌─────────────────┐  ┌─────────────┐ │      │
│  │  │Random Forest│  │Isolation Forest  │  │ Rule-based  │ │      │
│  │  │(Supervised) │  │(Unsupervised)    │  │ Inference   │ │      │
│  │  │Multi-class  │  │Anomaly Detection │  │ Threat Type │ │      │
│  │  └─────────────┘  └─────────────────┘  └─────────────┘ │      │
│  └──────────────────────────────────────────────────────────┘      │
│                                                                     │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  │
│  │Upload/PCAP │  │Realtime    │  │Dashboard/  │  │SBOM        │  │
│  │Analysis    │  │Capture     │  │History     │  │Security    │  │
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────┐      │
│  │                    SQLite (flows.db)                       │      │
│  │  flows table  │  analysis_history table                   │      │
│  └──────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Training Pipeline                                │
│  CIC-IDS CSVs → clean → scale → train RF + IF → save .pkl          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## How the NetGuard System Works

### Two Monitoring Modes

NetGuard processes network traffic through two distinct paths, both feeding the same ML decision engine:

#### 1. Passive Monitoring (File Upload)

```
User uploads PCAP/CSV
        │
        ▼
  ┌─────────────┐     ┌───────────┐     ┌──────────────┐
  │ PCAP? Run   │────▶│ Read CSV  │────▶│ clean_data() │
  │ cicflowmeter│     │ in chunks │     │ Drop NaN/Inf │
  │ → CSV       │     │ (50k rows)│     │ Strip cols   │
  └─────────────┘     └───────────┘     └──────┬───────┘
                                               │
                                               ▼
                                    ┌──────────────────┐
                                    │ Align to          │
                                    │ feature_names.pkl │
                                    │ (79 CIC features) │
                                    └──────┬───────────┘
                                           │
                                           ▼
                                    ┌──────────────────┐
                                    │ StandardScaler   │
                                    │ transform()      │
                                    └──────┬───────────┘
                                           │
                           ┌───────────────┼───────────────┐
                           ▼               ▼               ▼
                    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
                    │Random Forest│ │Isolation    │ │Rule-based   │
                    │predict()    │ │Forest       │ │Threat Type  │
                    │+ proba      │ │predict()    │ │Inference    │
                    │→ label +    │ │decision_fn()│ │(if anomaly  │
                    │  confidence │ │→ anomaly    │ │ + BENIGN)   │
                    │             │ │  score 0-1  │ │             │
                    └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
                           │               │               │
                           └───────────────┼───────────────┘
                                           ▼
                                    ┌──────────────────┐
                                    │ Hybrid Risk Score │
                                    │ Risk Level        │
                                    │ Threat Type + CVE │
                                    └──────┬───────────┘
                                           │
                                           ▼
                                    ┌──────────────────┐
                                    │ SQLite insert     │
                                    │ monitor_type =    │
                                    │ "passive"         │
                                    └──────────────────┘
```

**API Endpoint:** `POST /api/upload` (multipart file)

- Accepts `.pcap`, `.pcapng`, `.csv` files
- For PCAP files: first converts to CSV using `cicflowmeter`
- CSV is processed in 50,000-row chunks for memory efficiency
- Each flow gets: classification, confidence, anomaly_score, risk_score, risk_level, threat_type, CVE references

#### 2. Active Monitoring (Live Capture)

```
Network Interface (e.g., eth0, lo)
        │
        ▼
  ┌─────────────┐
  │ Scapy sniff │ ← 5-second capture windows
  │ (up to 50k  │   Requires sudo/root
  │  packets)   │
  └──────┬──────┘
         │
         ▼
  ┌──────────────────┐
  │ build_flows_from │
  │ _packets()       │
  │                  │
  │ - Group by       │
  │   normalized     │
  │   5-tuple        │
  │ - Aggregate:     │
  │   lengths, IATs, │
  │   TCP flags,     │
  │   windows, etc.  │
  │ - Output: 79     │
  │   CIC-style      │
  │   features       │
  └──────┬───────────┘
         │
         ▼
  ┌──────────────────┐
  │ classify_flows() │ ← Same RF + IF + rules
  │ (DecisionEngine) │   as passive mode
  └──────┬───────────┘
         │
         ▼
  ┌──────────────────┐
  │ SQLite insert     │
  │ monitor_type =    │
  │ "active"          │
  └──────────────────┘
```

**API Endpoints:**
- `POST /api/realtime/start?interface=eth0` — starts background capture thread
- `POST /api/realtime/stop` — stops capture
- `GET /api/realtime/status` — running state, capture count, flow counts
- `GET /api/realtime/interfaces` — list available NICs

The active monitor runs as a daemon thread. Every 5 seconds it:
1. Captures packets on the selected interface (Scapy `sniff()`)
2. Groups packets into flows by normalized 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol — direction-normalized so both sides merge)
3. Computes 79 CIC-style features per flow (packet lengths, inter-arrival times, TCP flags, window sizes, etc.)
4. Runs them through the same `classify_flows()` pipeline (scaler → RF → IF → risk scoring)
5. Inserts results into SQLite with `monitor_type='active'`

### ML Models — How They Work

#### Random Forest (Supervised Classification)

- **Algorithm:** `sklearn.ensemble.RandomForestClassifier` with 100 trees
- **Purpose:** Multi-class classification of network flows
- **Classes:** BENIGN, DDoS, PortScan, BruteForce, Web Attack, Bot, Infiltration, Heartbleed (from CIC-IDS-2017 dataset labels)
- **Output:** Predicted class label + confidence (max probability across classes)
- **When absent:** Falls back to labeling everything as BENIGN, relying entirely on the Isolation Forest

#### Isolation Forest (Unsupervised Anomaly Detection)

- **Algorithm:** `sklearn.ensemble.IsolationForest` with 100 trees, contamination=0.01
- **Purpose:** Detect flows that deviate from learned "normal" behavior
- **Training:** Trained ONLY on BENIGN flows (if labels exist) — learns what normal traffic looks like
- **Output:**
  - `predict() == -1` → anomaly
  - `anomaly_score = clip(0.5 - decision_function(), 0, 1)` → 0 (normal) to 1 (highly anomalous)

#### Hybrid Decision Logic

When both models are available:

```
IF Random Forest says BENIGN AND Isolation Forest flags anomaly:
  → infer_anomaly_threat_type() assigns a threat label
    based on flow features:
    - High SYN count + few packets → PortScan
    - SSH/RDP/FTP ports + TCP → Brute Force
    - Very high packet/byte rate → DDoS
    - HTTP/HTTPS ports + high bytes → Web Attack
    - Port 443 + specific pattern → Heartbleed
    - High rate + UDP → Bot
    - Unusual port + activity → Infiltration
    - Fallback by anomaly score → severity-based label

Risk Score Calculation:
  - BENIGN + anomaly: risk = anomaly_score × 0.6
  - BENIGN + no anomaly: risk = 0.0
  - Threat (supervised): risk = (confidence × 0.7) + (anomaly_score × 0.3)
  - Threat (no RF): risk = (pseudo_conf × 0.6) + (anomaly_score × 0.4) + 0.15

Risk Levels:
  - Critical: risk > 0.8
  - High:     risk > 0.6
  - Medium:   risk > 0.3
  - Low:      risk ≤ 0.3
```

### How Training Works

```
training_pipeline/train.py → main()
        │
        ▼
  ┌─────────────────────────────────┐
  │ 1. get_training_data()          │
  │    - Recursively find all CSVs  │
  │      under data/processed/      │
  │      cic_ids/flows/             │
  │    - 503 CSVs (Mon-Fri +        │
  │      DoomsDay synthetic)        │
  │    - Fallback: generate         │
  │      synthetic data             │
  │    - pd.concat all DataFrames   │
  └──────────┬──────────────────────┘
             │
             ▼
  ┌─────────────────────────────────┐
  │ 2. clean_data()                 │
  │    - Replace ±inf with NaN      │
  │    - Drop rows with NaN         │
  │    - Strip whitespace from      │
  │      column names               │
  └──────────┬──────────────────────┘
             │
             ▼
  ┌─────────────────────────────────┐
  │ 3. preprocess_data(mode='train')│
  │    - Drop non-predictive cols:  │
  │      Flow ID, Source IP, Dst IP,│
  │      Ports, Protocol, Timestamp │
  │    - Extract 'Label' as y       │
  │    - Keep numeric columns only  │
  │    - Fit StandardScaler on X    │
  │    - Fit LabelEncoder on y      │
  └──────────┬──────────────────────┘
             │
             ▼
  ┌─────────────────────────────────┐
  │ 4. Save artifacts               │
  │    - feature_names.pkl          │
  │    - scaler.pkl                 │
  │    - label_encoder.pkl          │
  └──────────┬──────────────────────┘
             │
             ▼
  ┌─────────────────────────────────┐
  │ 5. train_test_split             │
  │    80% train / 20% test         │
  │    stratified by label          │
  └──────┬──────────┬───────────────┘
         │          │
         ▼          ▼
  ┌────────────┐ ┌──────────────────┐
  │ 6a. Train  │ │ 6b. Train        │
  │ Random     │ │ Isolation Forest │
  │ Forest     │ │ on BENIGN-only   │
  │ (all data) │ │ rows from train  │
  │            │ │ set              │
  │ Evaluate:  │ │                  │
  │ accuracy,  │ │ contamination=   │
  │ precision, │ │ 0.01             │
  │ recall, F1 │ │                  │
  └────┬───────┘ └──────┬───────────┘
       │                │
       ▼                ▼
  ┌────────────┐ ┌──────────────────┐
  │ rf_model   │ │ if_model.pkl     │
  │ .pkl       │ │                  │
  └────────────┘ └──────────────────┘
       │
       ▼
  ┌─────────────────────────────────┐
  │ 7. Save metrics.json            │
  │    - accuracy, precision,       │
  │      recall, f1_score           │
  │    - confusion_matrix           │
  │    - training_info (samples,    │
  │      features, timestamp)       │
  └─────────────────────────────────┘
```

**Saved Artifacts (all under `training_pipeline/models/`):**

| File | Purpose |
|------|---------|
| `supervised/rf_model.pkl` | Trained Random Forest classifier |
| `unsupervised/if_model.pkl` | Trained Isolation Forest |
| `artifacts/scaler.pkl` | Fitted StandardScaler |
| `artifacts/label_encoder.pkl` | Fitted LabelEncoder (class names) |
| `artifacts/feature_names.pkl` | List of 79 feature column names |
| `metrics.json` | Training metrics for the API's Model Performance page |

**Data Sources:**
- **Primary:** CIC-IDS-2017 flow CSVs (493 processed from PCAP chunks via cicflowmeter)
- **Supplementary:** 10 synthetic "Dooms'Day" flow CSVs
- **Fallback:** `generate_synthetic_data.py` creates labeled synthetic flows if no CSVs exist

---

## Workflow 1: Security Monitoring & Alerting

**File:** `1_network_security_monitoring.json`

**Purpose:** Continuously monitors the NetGuard system health and threat levels. Sends alerts when anomaly rates or risk scores exceed configurable thresholds.

### Flow Diagram

```
Every 5 Minutes
     │
     ▼
Health Check (GET /api/health)
     │
     ├─── API Healthy? ──YES──┬── Get Dashboard Stats
     │                        │   (GET /api/dashboard/stats)
     │                        │
     │                        ├── Get Critical Anomalies
     │                        │   (GET /api/anomalies?risk_level=Critical)
     │                        │
     │                        └──────────┐
     │                                   ▼
     │                           Analyze Threats
     │                           (Code Node)
     │                           - Check anomaly rate vs threshold
     │                           - Check avg risk vs threshold
     │                           - Check critical threat count
     │                                   │
     │                            Alerts? ├──YES── Format Alert ──▶ Send Webhook/Slack
     │                                   │
     │                                   └──NO─── All Clear (NoOp)
     │
     └─── API Down? ─────── Format "API Down" Alert ──▶ Send Webhook
```

### Configurable Thresholds

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `ANOMALY_RATE_THRESHOLD` | `15` | Alert if anomaly rate exceeds this % |
| `RISK_SCORE_THRESHOLD` | `0.6` | Alert if avg risk score exceeds this |
| `CRITICAL_COUNT_THRESHOLD` | `5` | Alert if critical threats exceed this count |

### What It Checks

1. **API Health:** Is the backend responding? If not → critical alert
2. **Anomaly Rate:** `(total_anomalies / total_flows) × 100` — percentage of traffic flagged anomalous
3. **Average Risk Score:** Mean risk across all flows (0-1 scale)
4. **Critical Threat Count:** Number of flows classified as Critical risk level
5. **Top Source IPs:** Most active source IPs (potential attackers)

---

## Workflow 2: Automated File Analysis

**File:** `2_automated_file_analysis.json`

**Purpose:** Automatically detects new PCAP/CSV files and uploads them to NetGuard for ML analysis. Also accepts webhook triggers for on-demand analysis.

### Flow Diagram — Webhook Path

```
POST webhook /netguard-analyze
  Body: { "file_path": "/path/to/capture.pcap" }
     │
     ▼
Prepare Upload → cURL upload to /api/upload
     │
     ▼
Parse Response → Evaluate Results
     │
     ├── Threats Found? ──YES── Format Report ──▶ Send Alert + Respond
     │
     └── No Threats ──────────── Respond with summary
```

### Flow Diagram — Scheduled Scan Path

```
Every 10 Minutes
     │
     ▼
Get Watch Directory (from env var)
     │
     ▼
Scan for new .pcap/.pcapng/.csv files
(compare against processed log)
     │
     ├── New Files? ──YES── Split into items ──▶ Upload each via cURL
     │                                              │
     │                                              ▼
     │                                      Evaluate ──▶ Alert if threats
     │
     └── No New Files ──── Skip
```

### How File Analysis Works Internally

When a file hits `POST /api/upload`:

1. **Extension check:** `.pcap`, `.pcapng`, `.csv` — or magic-byte detection for extension-less files
2. **PCAP conversion:** If PCAP/PCAPNG, runs `cicflowmeter -f input.pcap -c output.csv`
3. **CSV chunked processing:** Reads CSV in 50,000-row chunks
4. **Per chunk:**
   - `clean_data()` — remove infinities/NaN
   - Align columns to `feature_names.pkl` (79 features)
   - `StandardScaler.transform()` — normalize features
   - `RandomForest.predict()` + `predict_proba()` — classification + confidence
   - `IsolationForest.predict()` + `decision_function()` — anomaly detection
   - Hybrid risk scoring and threat type inference
5. **Results:** Each flow gets id, classification, threat_type, CVE references, risk_score, risk_level
6. **Storage:** Flows inserted into SQLite (`monitor_type='passive'`), analysis metadata into `analysis_history`

---

## Workflow 3: Training Pipeline Automation

**File:** `3_training_pipeline.json`

**Purpose:** Periodically retrains the ML models on available data. Compares new model metrics against previous ones and reports results.

### Flow Diagram

```
Weekly (Monday 2AM) ──OR── POST webhook /netguard-train
     │
     ▼
Get Current Model Metrics (GET /api/models/metrics)
     │
     ▼
Save Pre-Training State (accuracy, f1, etc.)
     │
     ▼
Check Training Data Exists?
(count CSVs in data/processed/cic_ids/flows/)
     │
     ├── Data Available ──▶ Run training_pipeline/train.py
     │                       │
     │                       ▼
     │                 Evaluate Results
     │                 - Parse metrics.json
     │                 - Compare before/after
     │                 - accuracy_delta
     │                       │
     │                       ▼
     │                 Format Training Report
     │                 - Before vs After table
     │                 - Training details
     │                 - Improvement status
     │                       │
     │                       ▼
     │                 Send Report ──▶ Webhook/Slack
     │
     └── No Data ─────▶ Send "No Data" Warning
```

### Training Pipeline Details

The pipeline runs `train.py` which:

1. **Loads data:** Recursively finds all CSVs under `training_pipeline/data/processed/cic_ids/flows/`
   - Monday (98 CSVs), Tuesday (98), Wednesday (102), Thursday (98), Friday (97) = 493 CIC-IDS flow files
   - Plus 10 DoomsDay synthetic files = 503 total
   - If no CSVs found: generates synthetic data as fallback

2. **Preprocesses:**
   - Drops identifier columns (Flow ID, IPs, ports, protocol, timestamp)
   - Separates `Label` column as target (y)
   - Keeps only numeric features
   - Fits `StandardScaler` on features
   - Fits `LabelEncoder` on labels

3. **Trains two models:**
   - **Random Forest:** On all training data (80/20 stratified split). Evaluates with classification_report, confusion_matrix
   - **Isolation Forest:** Only on BENIGN flows from training set. Learns normal traffic patterns with contamination=0.01

4. **Saves 6 artifacts:** rf_model.pkl, if_model.pkl, scaler.pkl, label_encoder.pkl, feature_names.pkl, metrics.json

5. **Backend auto-loads:** The `DecisionEngine` loads these .pkl files at startup. After retraining, restart the backend (or it picks up changes on next init)

---

## Workflow 4: Daily Security Report

**File:** `4_daily_security_report.json`

**Purpose:** Generates a comprehensive daily security report by aggregating data from all API endpoints.

### Flow Diagram

```
Daily at 8:00 AM
     │
     ▼ (all 7 requests in parallel)
  ┌────────────────────────┐
  │ Dashboard Stats        │  GET /api/dashboard/stats
  │ Passive Stats          │  GET /api/dashboard/stats?monitor_type=passive
  │ Active Stats           │  GET /api/dashboard/stats?monitor_type=active
  │ All Anomalies          │  GET /api/anomalies?per_page=100
  │ Traffic Trends (24h)   │  GET /api/traffic/trends?points=24
  │ Model Metrics          │  GET /api/models/metrics
  │ Recent Analyses        │  GET /api/history?limit=20
  └────────┬───────────────┘
           │
           ▼
  Compile Daily Report (Code Node)
  Sections:
    📈 Overall Summary (flows, anomalies, rates)
    🔄 Passive vs Active breakdown
    🎯 Risk Distribution table
    ⚔️ Attack Distribution table
    🚨 Top 15 Threats (by risk score)
    🌐 Top Source/Destination IPs
    🤖 Model Status (loaded/not loaded)
    📁 Recent File Analyses
           │
           ├──▶ Send Report (Slack/Webhook)
           │
           └──▶ Critical Issues? ──YES── Send Urgent Alert
                                  │
                                  └──NO── Done
```

### Report Sections Explained

| Section | Data Source | What It Shows |
|---------|------------|---------------|
| Overall Summary | `/api/dashboard/stats` | Total flows, anomalies, rate, avg risk |
| Mode Breakdown | Same endpoint with `?monitor_type=` | Passive (uploads) vs Active (live capture) stats |
| Risk Distribution | `risk_distribution` from stats | Count of Critical/High/Medium/Low flows |
| Attack Distribution | `attack_distribution` from stats | Count per attack type (DDoS, PortScan, etc.) |
| Top Threats | `/api/anomalies` | Highest risk flows with IPs, classification, scores |
| Top IPs | `top_src_ips` / `top_dst_ips` | Most active source and destination IPs |
| Model Status | `/api/models/metrics` | Whether RF/IF/Scaler are loaded, accuracy metrics |
| Recent Analyses | `/api/history` | Last 20 file analyses with flow counts and risk |

---

## Workflow 5: Live Monitoring Management

**File:** `5_live_monitoring_management.json`

**Purpose:** Control the real-time packet capture system via webhook API, and automatically monitor its health with auto-restart capability.

### Flow Diagram — Webhook Control

```
POST webhook /netguard-monitor
  Body: { "action": "start|stop|status|interfaces", "interface": "eth0" }
     │
     ▼
Parse Action → Switch Router
     │
     ├── "start"      → POST /api/realtime/start?interface=eth0
     ├── "stop"       → POST /api/realtime/stop
     ├── "status"     → GET  /api/realtime/status
     └── "interfaces" → GET  /api/realtime/interfaces
     │
     ▼
Respond with API result
```

### Flow Diagram — Health Polling

```
Every 2 Minutes
     │
     ▼
Poll Monitor Status (GET /api/realtime/status)
     │
     ▼
Evaluate Monitor Health
  - Is it running?
  - Are flows being produced?
  - Should it be running? (env var)
     │
     ├── Needs Restart? ──YES── Auto-Restart (POST /start)
     │                           └── Send Alert
     │
     └── Alert Needed? ──YES── Send Health Alert
                         │
                         └──NO── Monitor OK (NoOp)
```

### How Live Monitoring Works Internally

The `RealtimeMonitor` class in `realtime_service.py`:

1. **Thread-based:** Runs as a Python daemon thread so it doesn't block FastAPI's async event loop
2. **Capture loop:**
   ```
   while self.running:
       packets = capture_packets(interface, duration=5)
       flows = build_flows_from_packets(packets)
       enriched = decision_engine.classify_flows(flows)
       db.insert_flows(enriched, monitor_type="active")
   ```
3. **Packet → Flow aggregation:**
   - IPv4/IPv6 + TCP/UDP/ICMP only
   - Normalized 5-tuple: sorts (src, dst) so both directions map to same flow
   - Computes per-flow: duration, packet counts, byte lengths, packet length stats (min/max/mean/std), inter-arrival times (IATs), TCP flag counts, window sizes, segment sizes, bulk rates, subflow metrics
   - Output: dict with 79 snake_case feature names matching `feature_names.pkl`

4. **Classification:** Same `classify_flows()` method as upload path — scaler → RF → IF → threat inference → risk scoring

5. **Requires `sudo`:** Raw packet capture needs root privileges. Run the backend with `sudo` for live capture.

---

## Setup & Configuration

### Prerequisites

- **n8n** installed and running (self-hosted or cloud)
- **NetGuard backend** running at a reachable URL (default: `http://localhost:8000`)
- **Notification endpoint** configured (Slack webhook, email, or custom webhook)

### Import Workflows

1. Open n8n dashboard
2. Go to **Workflows** → **Import from File**
3. Import each JSON file in order:
   - `1_network_security_monitoring.json`
   - `2_automated_file_analysis.json`
   - `3_training_pipeline.json`
   - `4_daily_security_report.json`
   - `5_live_monitoring_management.json`
4. Configure environment variables (see below)
5. Activate the workflows you need

### Docker Setup (Optional)

If running n8n via Docker alongside the NetGuard stack:

```yaml
# Add to your docker-compose.yml
n8n:
  image: n8nio/n8n
  ports:
    - "5678:5678"
  environment:
    - NETGUARD_API_URL=http://backend:8000
    - ALERT_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
    - ANOMALY_RATE_THRESHOLD=15
    - RISK_SCORE_THRESHOLD=0.6
    - CRITICAL_COUNT_THRESHOLD=5
    - NETGUARD_PROJECT_ROOT=/app
    - NETGUARD_AUTO_RESTART=true
    - NETGUARD_EXPECT_RUNNING=false
  volumes:
    - n8n_data:/home/node/.n8n
  depends_on:
    - backend
```

---

## Environment Variables

Configure these in n8n Settings → Environment Variables:

| Variable | Default | Used In | Description |
|----------|---------|---------|-------------|
| `NETGUARD_API_URL` | `http://localhost:8000` | All workflows | Base URL of the FastAPI backend |
| `ALERT_WEBHOOK_URL` | *(required)* | WF 1,2,3,5 | Slack/Teams/custom webhook for alerts |
| `REPORT_WEBHOOK_URL` | Falls back to `ALERT_WEBHOOK_URL` | WF 4 | Separate webhook for daily reports |
| `URGENT_WEBHOOK_URL` | Falls back to `ALERT_WEBHOOK_URL` | WF 4 | Webhook for urgent/critical alerts |
| `ANOMALY_RATE_THRESHOLD` | `15` | WF 1 | Max anomaly rate (%) before alerting |
| `RISK_SCORE_THRESHOLD` | `0.6` | WF 1 | Max avg risk score before alerting |
| `CRITICAL_COUNT_THRESHOLD` | `5` | WF 1 | Max critical threats before alerting |
| `NETGUARD_WATCH_DIR` | `training_pipeline/data/raw/bsnl/raw_flows` | WF 2 | Directory to scan for new files |
| `NETGUARD_PROCESSED_LOG` | `/tmp/netguard_processed_files.json` | WF 2 | Log of already-processed files |
| `NETGUARD_PROJECT_ROOT` | `/home/ictd/Desktop/Network/nal` | WF 3 | Absolute path to project root |
| `NETGUARD_AUTO_RESTART` | `true` | WF 5 | Auto-restart monitor if it stops |
| `NETGUARD_EXPECT_RUNNING` | `false` | WF 5 | Set `true` if monitor should always be running |
| `NETGUARD_DEFAULT_INTERFACE` | `lo` | WF 5 | Default NIC for auto-restart |

---

## API Endpoints Reference

All endpoints used by the n8n workflows:

| Method | Endpoint | Workflow | Purpose |
|--------|----------|----------|---------|
| `GET` | `/api/health` | WF 1 | Backend health check |
| `GET` | `/api/dashboard/stats` | WF 1, 4 | Aggregated dashboard metrics |
| `GET` | `/api/dashboard/stats?monitor_type=passive` | WF 4 | Upload-only stats |
| `GET` | `/api/dashboard/stats?monitor_type=active` | WF 4 | Live capture stats |
| `GET` | `/api/anomalies` | WF 1, 4 | Threat/anomaly list with filters |
| `GET` | `/api/traffic/trends` | WF 4 | Hourly traffic trend data |
| `GET` | `/api/models/metrics` | WF 3, 4 | Model performance + training info |
| `GET` | `/api/history` | WF 4 | List of past analyses |
| `POST` | `/api/upload` | WF 2 | Upload and analyze PCAP/CSV |
| `POST` | `/api/realtime/start` | WF 5 | Start live packet capture |
| `POST` | `/api/realtime/stop` | WF 5 | Stop live capture |
| `GET` | `/api/realtime/status` | WF 5 | Monitor status + flow counts |
| `GET` | `/api/realtime/interfaces` | WF 5 | List available network interfaces |

### Database Schema (SQLite — `flows.db`)

**`flows` table:**
```
id, analysis_id, upload_filename, timestamp,
src_ip, dst_ip, protocol, src_port, dst_port,
duration, total_fwd_packets, total_bwd_packets,
total_length_fwd, total_length_bwd,
flow_bytes_per_sec, flow_packets_per_sec,
classification, threat_type, cve_refs, classification_reason,
confidence, anomaly_score, risk_score, risk_level,
is_anomaly, monitor_type ('passive'|'active'), created_at
```

**`analysis_history` table:**
```
analysis_id, filename, monitor_type, uploaded_at, file_size,
total_flows, anomaly_count, avg_risk_score,
attack_distribution (JSON), risk_distribution (JSON),
report_details (JSON), created_at
```

---

## Customization Guide

### Adding Email Notifications

Replace the webhook HTTP Request nodes with n8n's built-in Email node:
1. Add credentials for your SMTP server in n8n
2. Replace `Send Alert (Webhook/Slack)` with an Email Send node
3. Map `$json.subject` to the email subject and `$json.body` to the HTML body

### Adding Telegram Alerts

1. Create a Telegram bot via @BotFather
2. Replace webhook nodes with the Telegram node
3. Set chat_id and map the message body

### Adding PagerDuty Integration

For critical alerts only:
1. Add a PagerDuty node after the "Critical Issues?" check
2. Create incidents for Critical severity alerts
3. Auto-resolve when the next check shows no critical threats

### Custom Thresholds Per Attack Type

Modify the "Analyze Threats" code node in Workflow 1 to add per-attack-type thresholds:
```javascript
const ddosCount = attackDist['DDoS'] || 0;
if (ddosCount > 50) {
  alerts.push({
    type: 'DDOS_SURGE',
    severity: 'Critical',
    message: `DDoS flow count ${ddosCount} exceeds threshold`
  });
}
```
