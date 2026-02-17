w# 📡 Project Report: Network Traffic Classification & Anomaly Detection

## 1. Project Overview
This project is an **end-to-end Machine Learning pipeline** for network security, designed to detect cyber threats in real-time. It processes network traffic flows (CSV/PCAP), classifies them into attack categories (e.g., DDoS, Brute Force), and identifies zero-day anomalies using a hybrid ML approach. The system features a **FastAPI backend** for inference and a **React dashboard** for visualization.

---

## 2. Technology Stack & Dependencies

### **Backend (Python)**
- **Framework:** `FastAPI` (High-performance API)
- **Server:** `Uvicorn` (ASGI server)
- **ML Libraries:** `scikit-learn`, `pandas`, `numpy`, `xgboost`, `joblib`
- **Packet Processing:** `scapy`, `cicflowmeter` (PCAP to CSV conversion)
- **Security:** `cyclonedx-bom` (SBOM generation)

### **Frontend (JavaScript)**
- **Framework:** `React.js` (Vite)
- **Styling:** `Tailwind CSS`
- **Visualization:** `Chart.js`, `react-chartjs-2`
- **Networking:** `Axios`

### **DevOps & Infrastructure**
- **Containerization:** `Docker`, `Docker Compose`
- **Version Control:** `Git`
- **Virtual Environment:** `venv`

---

## 3. System Architecture & Approach

### **A. Data Pipeline (`training_pipeline/`)**
1.  **Data Source:** CIC-IDS-2017 Dataset (Network Flows).
2.  **Preprocessing (`core/feature_engineering.py`):**
    -   **Cleaning:** Removal of Infinity/NaN values.
    -   **Feature Selection:** Keeps relevant numeric columns (e.g., Flow Duration, Packet Length).
    -   **Scaling:** `StandardScaler` for normalization.
    -   **Encoding:** `LabelEncoder` for attack labels.
3.  **Training Strategy (`train.py`):**
    -   **Hybrid Approach:** Trains two models in parallel.
        -   **Supervised (RandomForest):** For classifying *known* attacks.
        -   **Unsupervised (IsolationForest):** For detecting *unknown* anomalies (zero-day threats).
    -   **Artifacts:** Saves models (`rf_model.pkl`, `if_model.pkl`), scalers, and feature lists for consistent inference.

### **B. Backend Inference Engine (`backend/`)**
1.  **Decision Service (`decision_service.py`):**
    -   Loads trained artifacts on startup.
    -   Accepts PCAP or CSV uploads.
    -   Converts PCAP → CSV using `cicflowmeter`.
    -   **Hybrid Logic:** Combines Supervised Confidence + Anomaly Score to calculate a comprehensive **Risk Score**.
2.  **API Endpoints (`main.py`):**
    -   `/api/upload`: Real-time file analysis.
    -   `/api/dashboard/stats`: Aggregated security metrics.
    -   `/api/anomalies`: List of detected threats.

### **C. Frontend Dashboard (`frontend/`)**
1.  **Interactive UI:** Displays real-time traffic statistics.
2.  **Upload Interface:** Allows users to drag-and-drop traffic captures for analysis.
3.  **Visualization:** Charts for Protocol Distribution, Attack Types, and Anomaly Timelines.

---

## 4. Repository Structure

```
nal/
├── .venv/                  # Python Virtual Environment
├── backend/                # FastAPI Application
│   ├── app/
│   │   ├── services/       # ML Inference Logic
│   │   └── main.py         # API Gateway
│   └── Dockerfile          # Backend Container Config
├── frontend/               # React Application
│   ├── src/                # UI Components & Pages
│   └── Dockerfile          # Frontend Container Config
├── core/                   # Shared Code (Preprocessing)
├── training_pipeline/      # Model Training
│   ├── data/               # Raw & Processed Datasets (Gitignored)
│   ├── models/             # Trained .pkl Files (Gitignored)
│   ├── scripts/            # Helper scripts (synthetic data gen)
│   └── train.py            # Main Training Script
├── docker-compose.yml      # Container Orchestration
├── requirements.txt        # Python Dependencies
└── RUN_GUIDE.md            # Execution Instructions
```

---

## 5. Key Features Implemented
- ✅ **Automated Training Pipeline:** Handles missing labels gracefully (falls back to Unsupervised).
- ✅ **Real-time Inference:** Supports PCAP and CSV files.
- ✅ **Hybrid Risk Scoring:** Weights known vs. unknown threats.
- ✅ **Robust Error Handling:** System recovers if models are missing/mismatched.
- ✅ **Docker Support:** Full containerization for easy deployment.
- ✅ **Responsive Dashboard:** Modern UI with Tailwind CSS.

---

## 6. Future Roadmap
- [ ] Database integration (PostgreSQL) for long-term history.
- [ ] User Authentication (OAuth2).
- [ ] Live Packet Capture (streaming analysis from network interface).
