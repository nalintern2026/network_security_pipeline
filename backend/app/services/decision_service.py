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
from typing import Callable, Optional

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.feature_engineering import clean_data, preprocess_data
from app.classification_config import (
    risk_level_from_score,
    infer_anomaly_threat_type,
    get_threat_info,
    build_classification_reason,
)

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
        self._supervised_fallback_logged = False
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
                if self.label_encoder is None:
                    logger.warning("Label encoder artifact is None. Supervised predictions are disabled.")
            
            if FEATURE_NAMES_PATH.exists():
                with open(FEATURE_NAMES_PATH, 'rb') as f:
                    self.feature_names = pickle.load(f)
            
            logger.info("Models loaded successfully.")
        except Exception as e:
            logger.error(f"Error loading artifacts: {e}")

        if not self.rf_model or not self.label_encoder:
            logger.warning(
                "Supervised pipeline inactive (rf_model or label_encoder missing). "
                "System will run unsupervised anomaly detection only."
            )


    def analyze_file(
        self,
        file_path: str,
        file_type: str,
        include_flows: bool = True,
        source_filename: Optional[str] = None,
        on_chunk_processed: Optional[Callable[[list], int]] = None,
        chunk_size: int = 50000
    ) -> dict:
        """
        Analyze a network capture file (PCAP or CSV).
        
        Args:
            file_path: Path to the uploaded file.
            file_type: 'pcap', 'pcapng', or 'csv'.
            
        Returns:
            Analysis results dict.
        """
        process_id = str(uuid.uuid4())[:8]
        display_filename = source_filename or Path(file_path).name
        logger.info(f"Starting analysis {process_id} for file: {file_path}")
        should_cleanup_csv = False
        csv_path = file_path
        try:
            # 1. PCAP/PCAPNG only: convert to CSV with cicflowmeter; then same pipeline as CSV
            if file_type in ['pcap', 'pcapng']:
                csv_path = self._convert_pcap_to_csv(file_path, process_id)
                should_cleanup_csv = True
            # 2. From here on: csv_path is always a CSV (uploaded CSV or converted from pcap). Same flow.

            attack_counts = {}
            risk_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            protocol_distribution = {}
            anomaly_breakdown = {}
            attack_flow_samples = {}
            top_anomaly_flows = []
            top_risk_flows = []
            rows = [] if include_flows else None
            sample_flows = []
            total_flows = 0
            anomaly_count = 0
            risk_score_sum = 0.0

            def _safe_int(value):
                if value is None or pd.isna(value):
                    return None
                try:
                    return int(float(value))
                except Exception:
                    return None

            def _safe_float(value):
                if value is None or pd.isna(value):
                    return None
                try:
                    return float(value)
                except Exception:
                    return None

            def _top_n_append(items, row, key, limit=10):
                items.append(row)
                items.sort(key=lambda x: x.get(key, 0) or 0, reverse=True)
                if len(items) > limit:
                    del items[limit:]

            has_rows = False
            for chunk in pd.read_csv(csv_path, chunksize=chunk_size, low_memory=False):
                if chunk is None or chunk.empty:
                    continue

                df_clean = clean_data(chunk)
                if df_clean.empty:
                    continue

                has_rows = True

                if self.feature_names is not None:
                    for col in self.feature_names:
                        if col not in df_clean.columns:
                            df_clean[col] = 0
                    df_features = df_clean[self.feature_names]
                else:
                    df_features = df_clean.select_dtypes(include=[np.number])

                if self.scaler:
                    X_scaled = self.scaler.transform(df_features)
                else:
                    logger.warning("Scaler not loaded! Skipping scaling (Predictions will be wrong).")
                    X_scaled = df_features.values

                if self.rf_model and self.label_encoder:
                    y_pred = self.rf_model.predict(X_scaled)
                    y_prob = self.rf_model.predict_proba(X_scaled)
                    confidences = np.max(y_prob, axis=1)
                    labels = self.label_encoder.inverse_transform(y_pred)
                else:
                    labels = ["BENIGN"] * len(df_clean)
                    confidences = [0.5] * len(df_clean)
                    if not self._supervised_fallback_logged:
                        logger.warning(
                            "No supervised model available for inference. "
                            "Using BENIGN fallback labels with anomaly-based risk scoring."
                        )
                        self._supervised_fallback_logged = True

                if self.if_model:
                    anomaly_scores_raw = self.if_model.decision_function(X_scaled)
                    anomaly_scores = 0.5 - anomaly_scores_raw
                    anomaly_scores = np.clip(anomaly_scores, 0, 1)
                    is_anomaly = self.if_model.predict(X_scaled) == -1
                else:
                    anomaly_scores = [0.0] * len(df_clean)
                    is_anomaly = [False] * len(df_clean)

                chunk_rows = []
                for i in range(len(df_clean)):
                    original_lbl = str(labels[i])
                    lbl = original_lbl
                    conf = float(confidences[i])
                    anom_score = float(anomaly_scores[i])
                    is_anom = bool(is_anomaly[i])

                    # Unsupervised override: infer threat type from flow features + anomaly score (more accurate than score-only buckets)
                    if is_anom and lbl == 'BENIGN':
                        # Build flow feature dict from current row (same names as we use below for row)
                        duration = df_clean.get('Flow Duration', df_clean.get('flow_duration', None)).iloc[i] if 'Flow Duration' in df_clean or 'flow_duration' in df_clean else None
                        flow_bytes_s = df_clean.get('Flow Bytes/s', df_clean.get('flow_byts_s', None)).iloc[i] if 'Flow Bytes/s' in df_clean or 'flow_byts_s' in df_clean else None
                        flow_pkts_s = df_clean.get('Flow Packets/s', df_clean.get('flow_pkts_s', None)).iloc[i] if 'Flow Packets/s' in df_clean or 'flow_pkts_s' in df_clean else None
                        tot_fwd = df_clean.get('Total Fwd Packets', df_clean.get('tot_fwd_pkts', None)).iloc[i] if 'Total Fwd Packets' in df_clean or 'tot_fwd_pkts' in df_clean else None
                        tot_bwd = df_clean.get('Total Bwd Packets', df_clean.get('tot_bwd_pkts', None)).iloc[i] if 'Total Bwd Packets' in df_clean or 'tot_bwd_pkts' in df_clean else None
                        totlen_fwd = df_clean.get('Total Length Fwd Packets', df_clean.get('totlen_fwd_pkts', None)).iloc[i] if 'Total Length Fwd Packets' in df_clean or 'totlen_fwd_pkts' in df_clean else None
                        totlen_bwd = df_clean.get('Total Length Bwd Packets', df_clean.get('totlen_bwd_pkts', None)).iloc[i] if 'Total Length Bwd Packets' in df_clean or 'totlen_bwd_pkts' in df_clean else None
                        dst_port = df_clean.get('Destination Port', df_clean.get('dst_port', None)).iloc[i] if 'Destination Port' in df_clean or 'dst_port' in df_clean else None
                        proto = df_clean.get('Protocol', df_clean.get('protocol', None)).iloc[i] if 'Protocol' in df_clean or 'protocol' in df_clean else None
                        syn_cnt = df_clean.get('SYN Flag Count', df_clean.get('syn_flag_cnt', None)).iloc[i] if 'SYN Flag Count' in df_clean or 'syn_flag_cnt' in df_clean else None
                        flow_features = {
                            "duration": duration, "flow_duration": duration,
                            "flow_bytes_per_sec": flow_bytes_s, "flow_byts_s": flow_bytes_s,
                            "flow_packets_per_sec": flow_pkts_s, "flow_pkts_s": flow_pkts_s,
                            "total_fwd_packets": tot_fwd, "tot_fwd_pkts": tot_fwd,
                            "total_bwd_packets": tot_bwd, "tot_bwd_pkts": tot_bwd,
                            "total_length_fwd": totlen_fwd, "totlen_fwd_pkts": totlen_fwd,
                            "total_length_bwd": totlen_bwd, "totlen_bwd_pkts": totlen_bwd,
                            "dst_port": dst_port, "Destination Port": dst_port,
                            "protocol": proto, "Protocol": proto,
                            "syn_flag_cnt": syn_cnt, "SYN Flag Count": syn_cnt,
                        }
                        lbl = infer_anomaly_threat_type(flow_features, anom_score)

                    if lbl == 'BENIGN':
                        risk = anom_score * 0.6
                    else:
                        if self.rf_model and self.label_encoder:
                            risk = (conf * 0.7) + (anom_score * 0.3)
                        else:
                            pseudo_conf = max(conf, min(1.0, 0.55 + (0.45 * anom_score)))
                            risk = (pseudo_conf * 0.6) + (anom_score * 0.4) + 0.15

                    risk = float(np.clip(risk, 0, 1))
                    risk_level = risk_level_from_score(risk)
                    is_supervised_threat = not (is_anom and original_lbl == 'BENIGN')
                    threat_info = get_threat_info(lbl)
                    # Ensure threat_type is always set (so UI never shows "undefined")
                    threat_type_val = (threat_info.get("threat_type") or lbl or "Unknown").strip()
                    cve_refs_str = ",".join(threat_info["cve_refs"]) if threat_info.get("cve_refs") else ""
                    classification_reason = build_classification_reason(
                        lbl, is_supervised_threat, conf, anom_score, risk_level
                    )

                    src_ip = df_clean.get('Source IP', df_clean.get('src_ip', '0.0.0.0')).iloc[i] if 'Source IP' in df_clean or 'src_ip' in df_clean else 'N/A'
                    dst_ip = df_clean.get('Destination IP', df_clean.get('dst_ip', '0.0.0.0')).iloc[i] if 'Destination IP' in df_clean or 'dst_ip' in df_clean else 'N/A'
                    proto = df_clean.get('Protocol', df_clean.get('protocol', 'TCP')).iloc[i]

                    src_port = df_clean.get('Source Port', df_clean.get('src_port', None)).iloc[i] if 'Source Port' in df_clean or 'src_port' in df_clean else None
                    dst_port = df_clean.get('Destination Port', df_clean.get('dst_port', None)).iloc[i] if 'Destination Port' in df_clean or 'dst_port' in df_clean else None
                    duration = df_clean.get('Flow Duration', df_clean.get('flow_duration', None)).iloc[i] if 'Flow Duration' in df_clean or 'flow_duration' in df_clean else None
                    flow_bytes_s = df_clean.get('Flow Bytes/s', df_clean.get('flow_byts_s', None)).iloc[i] if 'Flow Bytes/s' in df_clean or 'flow_byts_s' in df_clean else None
                    flow_packets_s = df_clean.get('Flow Packets/s', df_clean.get('flow_pkts_s', None)).iloc[i] if 'Flow Packets/s' in df_clean or 'flow_pkts_s' in df_clean else None
                    tot_fwd_pkts = df_clean.get('Total Fwd Packets', df_clean.get('tot_fwd_pkts', None)).iloc[i] if 'Total Fwd Packets' in df_clean or 'tot_fwd_pkts' in df_clean else None
                    tot_bwd_pkts = df_clean.get('Total Bwd Packets', df_clean.get('tot_bwd_pkts', None)).iloc[i] if 'Total Bwd Packets' in df_clean or 'tot_bwd_pkts' in df_clean else None
                    totlen_fwd = df_clean.get('Total Length Fwd Packets', df_clean.get('totlen_fwd_pkts', None)).iloc[i] if 'Total Length Fwd Packets' in df_clean or 'totlen_fwd_pkts' in df_clean else None
                    totlen_bwd = df_clean.get('Total Length Bwd Packets', df_clean.get('totlen_bwd_pkts', None)).iloc[i] if 'Total Length Bwd Packets' in df_clean or 'totlen_bwd_pkts' in df_clean else None

                    row = {
                        "id": str(uuid.uuid4())[:8],
                        "analysis_id": process_id,
                        "upload_filename": display_filename,
                        "src_ip": str(src_ip) if src_ip is not None else "N/A",
                        "dst_ip": str(dst_ip) if dst_ip is not None else "N/A",
                        "src_port": _safe_int(src_port),
                        "dst_port": _safe_int(dst_port),
                        "protocol": str(proto) if proto is not None else "Unknown",
                        "duration": _safe_float(duration),
                        "total_fwd_packets": _safe_int(tot_fwd_pkts),
                        "total_bwd_packets": _safe_int(tot_bwd_pkts),
                        "total_length_fwd": _safe_int(totlen_fwd),
                        "total_length_bwd": _safe_int(totlen_bwd),
                        "flow_bytes_per_sec": _safe_float(flow_bytes_s),
                        "flow_packets_per_sec": _safe_float(flow_packets_s),
                        "timestamp": pd.Timestamp.now().isoformat(),
                        "classification": lbl,
                        "threat_type": threat_type_val,
                        "cve_refs": cve_refs_str,
                        "classification_reason": classification_reason,
                        "confidence": conf,
                        "anomaly_score": anom_score,
                        "risk_score": risk,
                        "risk_level": risk_level,
                        "is_anomaly": is_anom,
                    }
                    chunk_rows.append(row)

                    total_flows += 1
                    anomaly_count += 1 if is_anom else 0
                    risk_score_sum += risk
                    risk_dist[risk_level] += 1
                    attack_counts[lbl] = attack_counts.get(lbl, 0) + 1
                    protocol_distribution[row["protocol"]] = protocol_distribution.get(row["protocol"], 0) + 1

                    if is_anom or lbl != "BENIGN":
                        anomaly_breakdown[lbl] = anomaly_breakdown.get(lbl, 0) + 1
                        _top_n_append(top_anomaly_flows, {
                            "id": row["id"],
                            "classification": row["classification"],
                            "threat_type": row["threat_type"],
                            "cve_refs": row["cve_refs"],
                            "classification_reason": row["classification_reason"],
                            "src_ip": row["src_ip"],
                            "dst_ip": row["dst_ip"],
                            "protocol": row["protocol"],
                            "anomaly_score": row["anomaly_score"],
                            "risk_score": row["risk_score"],
                            "risk_level": row["risk_level"],
                        }, "anomaly_score")

                    _top_n_append(top_risk_flows, {
                        "id": row["id"],
                        "classification": row["classification"],
                        "threat_type": row["threat_type"],
                        "cve_refs": row["cve_refs"],
                        "classification_reason": row["classification_reason"],
                        "src_ip": row["src_ip"],
                        "dst_ip": row["dst_ip"],
                        "protocol": row["protocol"],
                        "anomaly_score": row["anomaly_score"],
                        "risk_score": row["risk_score"],
                        "risk_level": row["risk_level"],
                    }, "risk_score")

                    if len(sample_flows) < 10:
                        sample_flows.append(row)

                    attack_sample_key = row["classification"]
                    if attack_sample_key not in attack_flow_samples:
                        attack_flow_samples[attack_sample_key] = []
                    if len(attack_flow_samples[attack_sample_key]) < 5:
                        attack_flow_samples[attack_sample_key].append({
                            "id": row["id"],
                            "classification": row["classification"],
                            "threat_type": row["threat_type"],
                            "cve_refs": row["cve_refs"],
                            "classification_reason": row["classification_reason"],
                            "src_ip": row["src_ip"],
                            "dst_ip": row["dst_ip"],
                            "protocol": row["protocol"],
                            "risk_level": row["risk_level"],
                            "risk_score": row["risk_score"],
                            "anomaly_score": row["anomaly_score"],
                        })

                if on_chunk_processed and chunk_rows:
                    on_chunk_processed(chunk_rows)

                if include_flows and rows is not None:
                    rows.extend(chunk_rows)

            if not has_rows:
                logger.warning("Loaded CSV is empty after cleaning.")
                return {"error": "File is empty or could not be processed."}

            report_details = {
                "protocol_distribution": protocol_distribution,
                "anomaly_breakdown": anomaly_breakdown,
                "risk_breakdown": risk_dist,
                "top_anomaly_flows": top_anomaly_flows,
                "top_risk_flows": top_risk_flows,
                "attack_flow_samples": attack_flow_samples,
            }

            return {
                "id": process_id,
                "filename": display_filename,
                "total_flows": total_flows,
                "attack_distribution": attack_counts,
                "risk_distribution": risk_dist,
                "anomaly_count": anomaly_count,
                "avg_risk_score": (risk_score_sum / total_flows) if total_flows else 0.0,
                "sample_flows": sample_flows,
                "report_details": report_details,
                "flows": rows if include_flows and rows is not None else []
            }
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            return {"error": str(e)}
        finally:
            if should_cleanup_csv and os.path.exists(csv_path):
                os.remove(csv_path)

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
        logger.info("PCAP/PCAPNG conversion done; starting flow analysis (same as CSV path).")
        return str(csv_path)

# Singleton instance
decision_engine = DecisionEngine()
