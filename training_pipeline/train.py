"""
Main Training Pipeline Script.
Orchestrates data loading, preprocessing, model training (supervised & unsupervised), and artifacts saving.
"""
import sys
import pickle
import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
import pandas as pd
import numpy as np
import logging
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from core.feature_engineering import load_data, clean_data, preprocess_data, save_artifacts

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Paths
# Look for data in processed/cic_ids/flows (recursive)
RAW_DATA_DIR = PROJECT_ROOT / "training_pipeline" / "data" / "processed" / "cic_ids" / "flows"
MODELS_DIR = PROJECT_ROOT / "training_pipeline" / "models"
SUPERVISED_MODEL_PATH = MODELS_DIR / "supervised" / "rf_model.pkl"
UNSUPERVISED_MODEL_PATH = MODELS_DIR / "unsupervised" / "if_model.pkl"
ARTIFACTS_DIR = MODELS_DIR / "artifacts"
CAPTURE_CACHE_DIR = PROJECT_ROOT / "training_pipeline" / "data" / "processed" / "captures_converted"


def _pick_cicflowmeter() -> str | None:
    """Pick a runnable cicflowmeter binary from common locations."""
    env_path = os.environ.get("CICFLOWMETER_BIN")
    candidates: list[Path | str] = []
    if env_path:
        candidates.extend([Path(env_path), env_path])

    # Common project-local and runtime paths
    candidates.extend(
        [
            PROJECT_ROOT / "backend" / ".venv" / "bin" / "cicflowmeter",
            PROJECT_ROOT / ".venv" / "bin" / "cicflowmeter",
            "cicflowmeter",
        ]
    )

    for candidate in candidates:
        if isinstance(candidate, Path):
            if candidate.exists() and candidate.is_file() and os.access(str(candidate), os.X_OK):
                return str(candidate)
        else:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
    return None


def _training_roots() -> list[Path]:
    """
    Build recursive training roots.
    Optional env:
      - TRAINING_DATA_ROOTS=/abs/path/one:/abs/path/two
    """
    env_roots = os.environ.get("TRAINING_DATA_ROOTS", "").strip()
    if env_roots:
        roots = [Path(p).expanduser().resolve() for p in env_roots.split(os.pathsep) if p.strip()]
        # Keep existing default too so current behavior still works.
        roots.append(RAW_DATA_DIR)
    else:
        roots = [RAW_DATA_DIR]

    # De-duplicate while preserving order.
    seen: set[Path] = set()
    unique_roots: list[Path] = []
    for root in roots:
        if root not in seen:
            unique_roots.append(root)
            seen.add(root)
    return unique_roots


def _discover_files(roots: list[Path]) -> tuple[list[Path], list[Path]]:
    """Recursively discover csv and capture files across roots."""
    csv_files: list[Path] = []
    capture_files: list[Path] = []
    capture_exts = {".pcap", ".pcapng"}
    for root in roots:
        if not root.exists():
            logger.warning(f"Training data root not found: {root}")
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            ext = p.suffix.lower()
            if ext == ".csv":
                csv_files.append(p)
            elif ext in capture_exts:
                capture_files.append(p)
    return csv_files, capture_files


def _convert_captures_to_csv(capture_files: list[Path]) -> list[Path]:
    """
    Convert pcap/pcapng captures into flow CSVs using cicflowmeter.
    Existing outputs are reused so repeated training runs are incremental.
    """
    if not capture_files:
        return []

    cicflowmeter_bin = _pick_cicflowmeter()
    if not cicflowmeter_bin:
        logger.warning(
            "Found capture files (.pcap/.pcapng) but cicflowmeter is not available. "
            "Set CICFLOWMETER_BIN or install cicflowmeter in an active environment."
        )
        return []

    CAPTURE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    out_csvs: list[Path] = []
    total = len(capture_files)
    for i, capture in enumerate(sorted(capture_files), 1):
        safe_name = str(capture).replace("/", "__").replace(":", "_")
        out_csv = CAPTURE_CACHE_DIR / f"{safe_name}.csv"
        if out_csv.exists() and out_csv.stat().st_size > 0:
            out_csvs.append(out_csv)
            continue

        logger.info(f"[Capture->CSV {i}/{total}] {capture}")
        result = subprocess.run(
            [cicflowmeter_bin, "-f", str(capture), "-c", str(out_csv)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.warning(
                f"cicflowmeter failed for {capture} (exit={result.returncode}). "
                f"stderr={result.stderr.strip()[:300]}"
            )
            continue
        if out_csv.exists() and out_csv.stat().st_size > 0:
            out_csvs.append(out_csv)

    return out_csvs


def get_training_data():
    """
    Load training data recursively from configured roots.
    Supports:
      - CSV files directly
      - pcap/pcapng (converted to CSV flows via cicflowmeter)
    Generates synthetic CSV only as final fallback when no data is discovered.
    """
    roots = _training_roots()
    csv_files, capture_files = _discover_files(roots)
    converted_csvs = _convert_captures_to_csv(capture_files)
    csv_files.extend(converted_csvs)
    # Deduplicate CSV paths
    csv_files = sorted({p.resolve() for p in csv_files})
    logger.info(
        f"Discovered training files from {len(roots)} roots: "
        f"{len(csv_files)} CSVs (including converted), {len(capture_files)} captures."
    )
    
    if not csv_files:
        logger.warning(f"No CSV files found in {RAW_DATA_DIR}. Generating synthetic data...")
        # Fallback to raw/cic_ids if flows are empty (for synthetic)
        RAW_SYNTHETIC = PROJECT_ROOT / "training_pipeline" / "data" / "raw" / "cic_ids"
        sys.path.append(str(PROJECT_ROOT / "training_pipeline" / "scripts"))
        try:
            from generate_synthetic_data import generate_data as gen_synthetic
            gen_synthetic()
            csv_files = list(RAW_SYNTHETIC.glob("*.csv"))
        except ImportError:
            logger.error("Could not find synthetic data generator script.")
        
    logger.info(f"Loading {len(csv_files)} CSV files for training.")

    dfs = []
    labeled_files = 0
    unlabeled_files = 0
    for f in csv_files:
        df = load_data(str(f))
        if not df.empty:
            has_label = "Label" in df.columns
            labeled_files += 1 if has_label else 0
            unlabeled_files += 0 if has_label else 1
            dfs.append(df)
    logger.info(
        f"Loaded datasets: labeled_files={labeled_files}, unlabeled_files={unlabeled_files}"
    )

    if not dfs:
        raise ValueError("No data loaded!")
        
    return pd.concat(dfs, ignore_index=True)


def train_supervised(X_train, y_train, X_test, y_test, label_encoder):
    """Train Random Forest Classifier. Returns metrics dict for API."""
    logger.info("Training Supervised Model (Random Forest)...")
    
    # Initialize Model
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    
    # Train
    rf.fit(X_train, y_train)
    
    # Evaluate
    y_pred = rf.predict(X_test)
    logger.info("Supervised Model Evaluation:")
    logger.info(f"\n{classification_report(y_test, y_pred, target_names=label_encoder.classes_)}")
    
    # Save
    SUPERVISED_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(SUPERVISED_MODEL_PATH, 'wb') as f:
        pickle.dump(rf, f)
    logger.info(f"Supervised model saved to {SUPERVISED_MODEL_PATH}")

    # Build metrics for API (Model Performance page)
    report = classification_report(y_test, y_pred, target_names=label_encoder.classes_, output_dict=True)
    cm = confusion_matrix(y_test, y_pred)
    return {
        "name": "Random Forest",
        "accuracy": float(report["accuracy"]),
        "precision": float(report["macro avg"]["precision"]),
        "recall": float(report["macro avg"]["recall"]),
        "f1_score": float(report["macro avg"]["f1-score"]),
        "confusion_matrix": cm.tolist(),
        "classes": list(label_encoder.classes_),
        "roc_auc": float(report["accuracy"]),  # RF has no ROC in this script; reuse accuracy as placeholder
    }


def train_unsupervised(X_train, y_train, label_encoder):
    """
    Train Isolation Forest for Anomaly Detection.
    We train ONLY on Benign traffic to learn normality if labels exist.
    Otherwise train on all data.
    """
    logger.info("Training Unsupervised Model (Isolation Forest)...")
    
    # Identify Benign class
    benign_idx = -1
    if y_train is not None and label_encoder is not None:
        try:
            benign_idx = label_encoder.transform(['BENIGN'])[0]
        except ValueError:
            try:
                benign_idx = label_encoder.transform(['Benign'])[0]
            except ValueError:
                pass

    if benign_idx != -1 and y_train is not None:
        # Filter only benign samples for training
        X_benign = X_train[y_train == benign_idx]
        logger.info(f"Training on {len(X_benign)} benign samples out of {len(X_train)} total.")
    else:
        logger.warning("No labels or 'BENIGN' class found. Training on ALL data (assuming majority is normal).")
        X_benign = X_train

    # Isolation Forest
    # contamination='auto' or small value if we assume training set is clean
    iso_forest = IsolationForest(n_estimators=100, contamination=0.01, random_state=42, n_jobs=-1)
    
    iso_forest.fit(X_benign)
    
    # Save
    UNSUPERVISED_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(UNSUPERVISED_MODEL_PATH, 'wb') as f:
        pickle.dump(iso_forest, f)
    logger.info(f"Unsupervised model saved to {UNSUPERVISED_MODEL_PATH}")


def main():
    logger.info("Starting Training Pipeline...")
    
    # 1. Load Data
    try:
        df = get_training_data()
    except Exception as e:
        logger.error(f"Failed to load data: {e}")
        return
    
    # 2. Clean Data
    df = clean_data(df)
    
    # 3. Preprocess (Scale & Encode)
    # Note: If 'Label' column is missing, y will be None
    X, y, scaler, label_encoder, feature_names = preprocess_data(df, target_col='Label', mode='train')
    
    # Save Feature names for later verification
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(ARTIFACTS_DIR / "feature_names.pkl", "wb") as f:
        pickle.dump(feature_names, f)

    # 4. Save Artifacts (Scaler, Encoder)
    # Handles None gracefully if implemented in feature_engineering or by pickle
    save_artifacts(scaler, label_encoder, ARTIFACTS_DIR)
    
    # 5. Split Data
    if y is not None:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    else:
        logger.warning("No 'Label' column found in data. Skipping Supervised Training.")
        X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)
        y_train, y_test = None, None
    
    # 6. Train Models
    supervised_metrics = None
    if y_train is not None:
        supervised_metrics = train_supervised(X_train, y_train, X_test, y_test, label_encoder)
    
    train_unsupervised(X_train, y_train, label_encoder)

    # 7. Save metrics for backend API (Model Performance page)
    n_total = len(X)
    n_train = len(X_train)
    n_test = len(X_test)
    training_info = {
        "dataset": "CIC-IDS / synthetic",
        "total_samples": n_total,
        "training_samples": n_train,
        "test_samples": n_test,
        "feature_count": X.shape[1] if hasattr(X, 'shape') else 0,
        "last_trained": datetime.now().isoformat(),
    }
    metrics_payload = {
        "training_info": training_info,
        "models": {},
    }
    if supervised_metrics:
        metrics_payload["models"]["random_forest"] = supervised_metrics
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    metrics_path = MODELS_DIR / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics_payload, f, indent=2)
    logger.info(f"Metrics saved to {metrics_path}")

    logger.info("Training Pipeline Completed.")


if __name__ == "__main__":
    main()
