"""
Generate synthetic network traffic data for testing the ML pipeline.
Creates a CSV file with features similar to CIC-IDS-2017.
"""
import pandas as pd
import numpy as np
from pathlib import Path

# Fix random seed for reproducibility
np.random.seed(42)

# Define output path
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data" / "raw" / "cic_ids"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE = OUTPUT_DIR / "synthetic_traffic.csv"

# Number of samples
N_SAMPLES = 5000

def generate_data():
    print(f"Generating {N_SAMPLES} synthetic flow records...")
    
    # Generate random features (70+ columns in real CICFlowMeter, we simulate keys ones)
    data = {
        'Flow Duration': np.random.exponential(1000, N_SAMPLES),
        'Total Fwd Packets': np.random.poisson(10, N_SAMPLES),
        'Total Backward Packets': np.random.poisson(8, N_SAMPLES),
        'Total Length of Fwd Packets': np.random.exponential(500, N_SAMPLES),
        'Total Length of Bwd Packets': np.random.exponential(400, N_SAMPLES),
        'Fwd Packet Length Max': np.random.uniform(60, 1500, N_SAMPLES),
        'Fwd Packet Length Min': np.random.uniform(0, 60, N_SAMPLES),
        'Fwd Packet Length Mean': np.random.uniform(40, 800, N_SAMPLES),
        'Fwd Packet Length Std': np.random.uniform(0, 200, N_SAMPLES),
        'Bwd Packet Length Max': np.random.uniform(60, 1500, N_SAMPLES),
        'Bwd Packet Length Min': np.random.uniform(0, 60, N_SAMPLES),
        'Bwd Packet Length Mean': np.random.uniform(40, 800, N_SAMPLES),
        'Bwd Packet Length Std': np.random.uniform(0, 200, N_SAMPLES),
        'Flow Bytes/s': np.random.exponential(50000, N_SAMPLES),
        'Flow Packets/s': np.random.exponential(100, N_SAMPLES),
        'Flow IAT Mean': np.random.exponential(50, N_SAMPLES),
        'Flow IAT Std': np.random.exponential(20, N_SAMPLES),
        'Flow IAT Max': np.random.exponential(200, N_SAMPLES),
        'Flow IAT Min': np.random.exponential(1, N_SAMPLES),
        'Fwd IAT Total': np.random.exponential(1000, N_SAMPLES),
        'Fwd IAT Mean': np.random.exponential(50, N_SAMPLES),
        'Fwd IAT Std': np.random.exponential(20, N_SAMPLES),
        'Fwd IAT Max': np.random.exponential(200, N_SAMPLES),
        'Fwd IAT Min': np.random.exponential(1, N_SAMPLES),
        'Bwd IAT Total': np.random.exponential(800, N_SAMPLES),
        'Bwd IAT Mean': np.random.exponential(40, N_SAMPLES),
        'Bwd IAT Std': np.random.exponential(15, N_SAMPLES),
        'Bwd IAT Max': np.random.exponential(150, N_SAMPLES),
        'Bwd IAT Min': np.random.exponential(1, N_SAMPLES),
        'Fwd PSH Flags': np.random.choice([0, 1], N_SAMPLES, p=[0.9, 0.1]),
        'Bwd PSH Flags': np.zeros(N_SAMPLES),
        'Fwd URG Flags': np.zeros(N_SAMPLES),
        'Bwd URG Flags': np.zeros(N_SAMPLES),
        'Fwd Header Length': np.random.randint(20, 60, N_SAMPLES) * 10,
        'Bwd Header Length': np.random.randint(20, 60, N_SAMPLES) * 8,
        'Fwd Packets/s': np.random.exponential(50, N_SAMPLES),
        'Bwd Packets/s': np.random.exponential(40, N_SAMPLES),
        'Min Packet Length': np.random.randint(0, 60, N_SAMPLES),
        'Max Packet Length': np.random.randint(60, 1500, N_SAMPLES),
        'Packet Length Mean': np.random.uniform(40, 800, N_SAMPLES),
        'Packet Length Std': np.random.uniform(0, 200, N_SAMPLES),
        'Packet Length Variance': np.random.uniform(0, 40000, N_SAMPLES),
        'FIN Flag Count': np.random.choice([0, 1], N_SAMPLES, p=[0.95, 0.05]),
        'SYN Flag Count': np.random.choice([0, 1], N_SAMPLES, p=[0.9, 0.1]),
        'RST Flag Count': np.random.choice([0, 1], N_SAMPLES, p=[0.99, 0.01]),
        'PSH Flag Count': np.random.choice([0, 1], N_SAMPLES, p=[0.8, 0.2]),
        'ACK Flag Count': np.random.choice([0, 1], N_SAMPLES, p=[0.4, 0.6]),
        'URG Flag Count': np.random.choice([0, 1], N_SAMPLES, p=[0.99, 0.01]),
        'CWE Flag Count': np.zeros(N_SAMPLES),
        'ECE Flag Count': np.zeros(N_SAMPLES),
        'Down/Up Ratio': np.random.choice([0, 1], N_SAMPLES),
        'Average Packet Size': np.random.uniform(40, 800, N_SAMPLES),
        'Avg Fwd Segment Size': np.random.uniform(40, 800, N_SAMPLES),
        'Avg Bwd Segment Size': np.random.uniform(40, 800, N_SAMPLES),
        'Fwd Header Length.1': np.random.randint(20, 60, N_SAMPLES) * 10,
        'Fwd Avg Bytes/Bulk': np.zeros(N_SAMPLES),
        'Fwd Avg Packets/Bulk': np.zeros(N_SAMPLES),
        'Fwd Avg Bulk Rate': np.zeros(N_SAMPLES),
        'Bwd Avg Bytes/Bulk': np.zeros(N_SAMPLES),
        'Bwd Avg Packets/Bulk': np.zeros(N_SAMPLES),
        'Bwd Avg Bulk Rate': np.zeros(N_SAMPLES),
        'Subflow Fwd Packets': np.random.poisson(10, N_SAMPLES),
        'Subflow Fwd Bytes': np.random.exponential(500, N_SAMPLES),
        'Subflow Bwd Packets': np.random.poisson(8, N_SAMPLES),
        'Subflow Bwd Bytes': np.random.exponential(400, N_SAMPLES),
        'Init_Win_bytes_forward': np.random.randint(0, 65535, N_SAMPLES),
        'Init_Win_bytes_backward': np.random.randint(0, 65535, N_SAMPLES),
        'act_data_pkt_fwd': np.random.poisson(5, N_SAMPLES),
        'min_seg_size_forward': np.random.choice([20, 32], N_SAMPLES),
        'Active Mean': np.random.exponential(100, N_SAMPLES),
        'Active Std': np.random.exponential(20, N_SAMPLES),
        'Active Max': np.random.exponential(200, N_SAMPLES),
        'Active Min': np.random.exponential(10, N_SAMPLES),
        'Idle Mean': np.random.exponential(5000, N_SAMPLES),
        'Idle Std': np.random.exponential(1000, N_SAMPLES),
        'Idle Max': np.random.exponential(8000, N_SAMPLES),
        'Idle Min': np.random.exponential(2000, N_SAMPLES),
    }

    # Generate Labels
    labels = np.random.choice(
        ['BENIGN', 'DDoS', 'PortScan', 'Bot', 'Infiltration', 'Web Attack', 'Brute Force'],
        N_SAMPLES,
        p=[0.7, 0.1, 0.05, 0.05, 0.02, 0.03, 0.05]
    )
    
    df = pd.DataFrame(data)
    df['Label'] = labels

    print(f"Saving to {OUTPUT_FILE}...")
    df.to_csv(OUTPUT_FILE, index=False)
    print("Done.")

if __name__ == "__main__":
    generate_data()
