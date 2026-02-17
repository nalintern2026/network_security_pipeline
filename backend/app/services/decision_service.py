"""
Decision Service for Network Traffic Analysis.
Handles model loading, traffic preprocessing, and hybrid inference (Supervised + Unsupervised).
"""
import os
import shutil
import pickle
import sys
import logging
import subprocess
import uuid
import pandas as pd
import numpy as np
from pathlib import Path

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.feature_engineering import clean_data, preprocess_data

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Model Paths
MODELS_DIR = PROJECT_ROOT / "training_pipeline" / "models"
SUPERVISED_MODEL_PATH = MODELS_DIR / "supervised" / "rf_model.pkl"
UNSUPERVISED_MODEL_PATH = MODELS_DIR / "unsupervised" / "if_model.pkl"
ARTIFACTS_DIR = MODELS_DIR / "artifacts"
SCALER_PATH = ARTIFACTS_DIR / "scaler.pkl"
LABEL_ENCODER_PATH = ARTIFACTS_DIR / "label_encoder.pkl"
FEATURE_NAMES_PATH = ARTIFACTS_DIR / "feature_names.pkl"

# Temp Dir for PCAP processing
TEMP_DIR = PROJECT_ROOT / "temp_processing"
TEMP_DIR.mkdir(exist_ok=True)

class DecisionEngine:
    def __init__(self):
        self.rf_model = None
        self.if_model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self._load_models()

    def _load_models(self):
        """Load trained models and artifacts from disk."""
        logger.info("Loading models...")
        
        # Supervised Model
        try:
            with open(SUPERVISED_MODEL_PATH, 'rb') as f:
                self.rf_model = pickle.load(f)
        except FileNotFoundError:
            logger.warning(f"Supervised model not found at {SUPERVISED_MODEL_PATH}. Skipping.")
        except Exception as e:
            logger.error(f"Error loading supervised model: {e}")

        # Unsupervised Model
        try:
            with open(UNSUPERVISED_MODEL_PATH, 'rb') as f:
                self.if_model = pickle.load(f)
        except FileNotFoundError:
            logger.warning(f"Unsupervised model not found at {UNSUPERVISED_MODEL_PATH}. Skipping.")
        except Exception as e:
            logger.error(f"Error loading unsupervised model: {e}")

        # Artifacts
        try:
            if SCALER_PATH.exists():
                with open(SCALER_PATH, 'rb') as f:
                    self.scaler = pickle.load(f)
            else:
                logger.warning("Scaler artifact not found.")

            if LABEL_ENCODER_PATH.exists():
                with open(LABEL_ENCODER_PATH, 'rb') as f:
                    self.label_encoder = pickle.load(f)
            
            if FEATURE_NAMES_PATH.exists():
                with open(FEATURE_NAMES_PATH, 'rb') as f:
                    self.feature_names = pickle.load(f)
            
            logger.info("Models loaded successfully.")
        except Exception as e:
            logger.error(f"Error loading artifacts: {e}")


    def analyze_file(self, file_path: str, file_type: str) -> dict:
        """
        Analyze a network capture file (PCAP or CSV).
        
        Args:
            file_path: Path to the uploaded file.
            file_type: 'pcap', 'pcapng', or 'csv'.
            
        Returns:
            Analysis results dict.
        """
        process_id = str(uuid.uuid4())[:8]
        logger.info(f"Starting analysis {process_id} for file: {file_path}")
        
        try:
            # 1. Convert PCAP to CSV if needed
            if file_type in ['pcap', 'pcapng']:
                csv_path = self._convert_pcap_to_csv(file_path, process_id)
            else:
                csv_path = file_path

            # 2. Load CSV
            df = pd.read_csv(csv_path)
            if df.empty:
                logger.warning("Loaded CSV is empty.")
                return {"error": "File is empty or could not be processed."}
                
            # 3. Clean & Preprocess
            df_clean = clean_data(df)
            
            # Align features with training data
            # Keep only numeric columns that were used in training
            if self.feature_names is not None:
                # Add missing cols with 0
                for col in self.feature_names:
                    if col not in df_clean.columns:
                        df_clean[col] = 0
                # Drop extra cols
                df_features = df_clean[self.feature_names]
            else:
                # Fallback: Just use numeric
                df_features = df_clean.select_dtypes(include=[np.number])

            # Scale
            if self.scaler:
                 X_scaled = self.scaler.transform(df_features)
            else:
                 logger.warning("Scaler not loaded! Skipping scaling (Predictions will be wrong).")
                 X_scaled = df_features.values
            
            # 4. Inference
            results = []
            
            # Supervised Prediction
            if self.rf_model:
                y_pred = self.rf_model.predict(X_scaled)
                y_prob = self.rf_model.predict_proba(X_scaled)
                confidences = np.max(y_prob, axis=1)
                
                # Decode labels
                labels = self.label_encoder.inverse_transform(y_pred) if self.label_encoder else y_pred
            else:
                labels = ["Unknown"] * len(df_clean)
                confidences = [0.0] * len(df_clean)

            # Unsupervised Anomaly Detection
            if self.if_model:
                # Isolation Forest: -1 is anomaly, 1 is normal
                # decision_function: lower is more anomalous
                anomaly_scores_raw = self.if_model.decision_function(X_scaled)
                # Normalize score to 0-1 range (approximate)
                # Typical range is -0.5 to 0.5. We invert so high = anomaly
                anomaly_scores = 0.5 - anomaly_scores_raw 
                anomaly_scores = np.clip(anomaly_scores, 0, 1) # Clip to 0-1
                is_anomaly = self.if_model.predict(X_scaled) == -1
            else:
                anomaly_scores = [0.0] * len(df_clean)
                is_anomaly = [False] * len(df_clean)

            # 5. Build Result
            attack_counts = {}
            risk_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            
            rows = []
            features_list = df_clean.to_dict('records') # Original data for display

            for i in range(len(df_clean)):
                lbl = labels[i]
                conf = confidences[i]
                anom_score = anomaly_scores[i]
                is_anom = is_anomaly[i]
                
                # Hybrid Risk Score Calculation
                # Weighted average of supervised confidence (if attack) and anomaly score
                if lbl == 'BENIGN':
                    risk = anom_score * 0.6  # Even if benign, high anomaly score implies risk
                else:
                    risk = (conf * 0.7) + (anom_score * 0.3)
                
                risk = float(np.clip(risk, 0, 1))
                
                risk_level = "Critical" if risk > 0.8 else "High" if risk > 0.6 else "Medium" if risk > 0.3 else "Low"
                risk_dist[risk_level] += 1
                attack_counts[lbl] = attack_counts.get(lbl, 0) + 1

                # Extract Flow Info (Source/Dest IP, Port, etc.) often not in features but in original df
                # We dropped them in preprocessing, but they might be in `df_clean` if we didn't drop them there yet.
                # `clean_data` only drops rows, not columns. `preprocess_data` drops columns.
                # So `df_clean` still has IPs if they were in the CSV.
                
                src_ip = df_clean.get('Source IP', df_clean.get('src_ip', '0.0.0.0')).iloc[i] if 'Source IP' in df_clean or 'src_ip' in df_clean else 'N/A'
                dst_ip = df_clean.get('Destination IP', df_clean.get('dst_ip', '0.0.0.0')).iloc[i] if 'Destination IP' in df_clean or 'dst_ip' in df_clean else 'N/A'
                proto = str(df_clean.get('Protocol', df_clean.get('protocol', 'TCP')).iloc[i])
                
                row = {
                    "id": str(uuid.uuid4())[:8],
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": proto,
                    "timestamp": pd.Timestamp.now().isoformat(), # We don't have packet time easily
                    "classification": lbl,
                    "confidence": float(conf),
                    "anomaly_score": float(anom_score),
                    "risk_score": risk,
                    "risk_level": risk_level,
                    "is_anomaly": bool(is_anom) or (lbl != 'BENIGN')
                }
                rows.append(row)

            # Cleanup Temp
            if file_type in ['pcap', 'pcapng'] and os.path.exists(csv_path):
                os.remove(csv_path)

            return {
                "id": process_id,
                "filename": Path(file_path).name,
                "total_flows": len(rows),
                "attack_distribution": attack_counts,
                "risk_distribution": risk_dist,
                "anomaly_count": sum(1 for r in rows if r['is_anomaly']),
                "avg_risk_score": float(np.mean([r['risk_score'] for r in rows])) if rows else 0.0,
                "flows": rows[:100] # Return top 100 for display
            }
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            return {"error": str(e)}

    def _convert_pcap_to_csv(self, pcap_path: str, process_id: str) -> str:
        """Run cicflowmeter to convert PCAP to CSV."""
        output_dir = TEMP_DIR / process_id
        output_dir.mkdir(parents=True, exist_ok=True)
        # cicflowmeter adds proper extension, so we give it the dir and file prefix or just output dir?
        # cicflowmeter -f file.pcap -c file.csv
        csv_name = f"{process_id}.csv"
        csv_path = output_dir / csv_name
        
        cmd = ["cicflowmeter", "-f", pcap_path, "-c", str(csv_path)]
        logger.info(f"Running: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"cicflowmeter failed: {result.stderr}")
            raise RuntimeError(f"Failed to convert PCAP to CSV: {result.stderr}")
            
        if not csv_path.exists():
             raise RuntimeError("CSV file was not created by cicflowmeter.")
             
        return str(csv_path)

# Singleton instance
decision_engine = DecisionEngine()
