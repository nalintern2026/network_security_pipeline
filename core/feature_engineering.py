"""
Feature engineering and preprocessing logic for network traffic classification.
"""
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import pickle
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# List of features to drop (IDs, timestamps, etc.)
DROP_COLS = [
    'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port',
    'Protocol', 'Timestamp', 'SimillarHTTP', 'Inbound'
]

# Ensure column names match CIC-IDS / CICFlowMeter output
FEATURE_COLS = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
    'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
    'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
    'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
    'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length',
    'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
    'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count',
    'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std',
    'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]


def load_data(filepath: str) -> pd.DataFrame:
    """Load dataset from CSV file."""
    try:
        df = pd.read_csv(filepath)
        logger.info(f"Loaded data from {filepath} with shape {df.shape}")
        return df
    except Exception as e:
        logger.error(f"Error loading data from {filepath}: {e}")
        return pd.DataFrame()


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """Clean dataset: handle infinite values and missing data."""
    # Replace infinite with NaN
    df = df.replace([np.inf, -np.inf], np.nan)
    # Drop rows with NaN
    initial_len = len(df)
    df = df.dropna()
    final_len = len(df)
    
    if initial_len != final_len:
        logger.info(f"Dropped {initial_len - final_len} rows with NaN/Inf values")

    # Rename columns to strip whitespace
    df.columns = df.columns.str.strip()
    
    return df


def preprocess_data(df: pd.DataFrame, target_col: str = 'Label', mode: str = 'train', scaler=None):
    """
    Complete preprocessing pipeline:
    1. Drop non-predictive columns
    2. Encode target variable (if present)
    3. Scale features
    
    Args:
        df: DataFrame
        target_col: Name of target column
        mode: 'train' or 'inference'
        scaler: Pre-fitted scaler (required for inference mode)
        
    Returns:
        X_scaled, y_encoded, scaler, label_encoder, X_numeric.columns
    """
    # 1. Drop columns irrelevant for ML (IPs, Ports, Time)
    cols_to_drop = [c for c in DROP_COLS if c in df.columns]
    if cols_to_drop:
        df = df.drop(columns=cols_to_drop)
        logger.info(f"Dropped columns: {cols_to_drop}")

    # 2. Separate Features and Target
    if target_col in df.columns:
        X = df.drop(columns=[target_col])
        y = df[target_col]
    else:
        X = df
        y = None

    # Handle numeric scaling
    # Ensure only numeric columns are selected for scaling
    X_numeric = X.select_dtypes(include=[np.number])
    
    # 3. Scaling
    if mode == 'train':
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_numeric)
    elif mode == 'inference':
        if scaler is None:
            raise ValueError("Scaler must be provided for inference mode.")
        X_scaled = scaler.transform(X_numeric)
    else:
        raise ValueError(f"Invalid mode: {mode}")

    # 4. Encoding Target
    label_encoder = None
    y_encoded = None
    if y is not None and mode == 'train':
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y)
    
    return X_scaled, y_encoded, scaler, label_encoder, X_numeric.columns


def save_artifacts(scaler, label_encoder, output_dir: Path):
    """Save preprocessing artifacts (scaler, label encoder)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    with open(output_dir / 'scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    
    with open(output_dir / 'label_encoder.pkl', 'wb') as f:
        pickle.dump(label_encoder, f)
        
    logger.info(f"Artifacts saved to {output_dir}")

