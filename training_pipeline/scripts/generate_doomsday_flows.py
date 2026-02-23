"""
Generate synthetic processed-flow CSV files for a "Dooms'Day" dataset.

Goals:
- Keep exact processed CIC-IDS schema (82 columns).
- Produce randomized file sizes and per-file traffic mixes.
- Mix Benign + multiple attack profiles in random order.
- Randomize severity pressure (medium/high/critical) per threat row.
"""
from __future__ import annotations

import argparse
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List


SCHEMA = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp",
    "flow_duration", "flow_byts_s", "flow_pkts_s", "fwd_pkts_s", "bwd_pkts_s",
    "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "pkt_len_max", "pkt_len_min", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
    "fwd_header_len", "bwd_header_len", "fwd_seg_size_min", "fwd_act_data_pkts",
    "flow_iat_mean", "flow_iat_max", "flow_iat_min", "flow_iat_std",
    "fwd_iat_tot", "fwd_iat_max", "fwd_iat_min", "fwd_iat_mean", "fwd_iat_std",
    "bwd_iat_tot", "bwd_iat_max", "bwd_iat_min", "bwd_iat_mean", "bwd_iat_std",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "ack_flag_cnt", "urg_flag_cnt", "ece_flag_cnt", "down_up_ratio",
    "pkt_size_avg", "init_fwd_win_byts", "init_bwd_win_byts",
    "active_max", "active_min", "active_mean", "active_std",
    "idle_max", "idle_min", "idle_mean", "idle_std",
    "fwd_byts_b_avg", "fwd_pkts_b_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg",
    "fwd_blk_rate_avg", "bwd_blk_rate_avg", "fwd_seg_size_avg", "bwd_seg_size_avg",
    "cwr_flag_count", "subflow_fwd_pkts", "subflow_bwd_pkts", "subflow_fwd_byts",
    "subflow_bwd_byts",
]

ATTACK_TYPES = [
    "Anomaly",
    "DDoS",
    "PortScan",
    "BruteForce",
    "Web Attack",
    "Bot",
    "Infiltration",
    "Heartbleed",
]

SEVERITIES = ["medium", "high", "critical"]
PROTO_POOL = [1, 6, 17, 47, 50, 51, 89, 132]
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 123, 443, 445, 587, 8080, 8443, 3389]


def rand_ip(private: bool = True) -> str:
    if private:
        family = random.choice(["10", "172", "192"])
        if family == "10":
            return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        if family == "172":
            return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
        return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def rate(num: float, dur_us: float) -> float:
    return num / max(dur_us / 1_000_000.0, 0.0002)


def base_row(ts: datetime) -> Dict[str, float]:
    proto = random.choice(PROTO_POOL)
    dur = random.randint(5_000, 4_000_000)
    fwd_pkts = random.randint(2, 80)
    bwd_pkts = random.randint(1, 70)
    fwd_mean = random.uniform(50.0, 700.0)
    bwd_mean = random.uniform(40.0, 650.0)
    fwd_bytes = int(fwd_pkts * fwd_mean)
    bwd_bytes = int(bwd_pkts * bwd_mean)
    total_pkts = fwd_pkts + bwd_pkts
    total_bytes = max(1, fwd_bytes + bwd_bytes)

    row = {
        "src_ip": rand_ip(True),
        "dst_ip": random.choice([rand_ip(True), rand_ip(False)]),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice(COMMON_PORTS),
        "protocol": proto,
        "timestamp": ts.isoformat(sep=" "),
        "flow_duration": dur,
        "flow_byts_s": round(rate(total_bytes, dur), 6),
        "flow_pkts_s": round(rate(total_pkts, dur), 6),
        "fwd_pkts_s": round(rate(fwd_pkts, dur), 6),
        "bwd_pkts_s": round(rate(bwd_pkts, dur), 6),
        "tot_fwd_pkts": fwd_pkts,
        "tot_bwd_pkts": bwd_pkts,
        "totlen_fwd_pkts": fwd_bytes,
        "totlen_bwd_pkts": bwd_bytes,
        "fwd_pkt_len_max": int(fwd_mean * random.uniform(1.1, 3.0)),
        "fwd_pkt_len_min": int(max(1.0, fwd_mean * random.uniform(0.02, 0.4))),
        "fwd_pkt_len_mean": round(fwd_mean, 6),
        "fwd_pkt_len_std": round(random.uniform(2.0, 220.0), 6),
        "bwd_pkt_len_max": int(bwd_mean * random.uniform(1.1, 3.0)),
        "bwd_pkt_len_min": int(max(1.0, bwd_mean * random.uniform(0.02, 0.4))),
        "bwd_pkt_len_mean": round(bwd_mean, 6),
        "bwd_pkt_len_std": round(random.uniform(2.0, 220.0), 6),
        "pkt_len_max": int(max(fwd_mean, bwd_mean) * random.uniform(1.2, 3.3)),
        "pkt_len_min": random.randint(1, 64),
        "pkt_len_mean": round((fwd_mean + bwd_mean) / 2.0, 6),
        "pkt_len_std": round(random.uniform(2.0, 250.0), 6),
        "pkt_len_var": round(random.uniform(10.0, 200_000.0), 6),
        "fwd_header_len": random.randint(20, 4096),
        "bwd_header_len": random.randint(20, 4096),
        "fwd_seg_size_min": random.randint(20, 64),
        "fwd_act_data_pkts": random.randint(1, max(1, fwd_pkts)),
        "flow_iat_mean": round(random.uniform(1.0, 10_000.0), 6),
        "flow_iat_max": round(random.uniform(5.0, 120_000.0), 6),
        "flow_iat_min": round(random.uniform(0.0, 2_000.0), 6),
        "flow_iat_std": round(random.uniform(0.01, 25_000.0), 6),
        "fwd_iat_tot": round(random.uniform(10.0, 800_000.0), 6),
        "fwd_iat_max": round(random.uniform(1.0, 250_000.0), 6),
        "fwd_iat_min": round(random.uniform(0.0, 2_000.0), 6),
        "fwd_iat_mean": round(random.uniform(0.1, 80_000.0), 6),
        "fwd_iat_std": round(random.uniform(0.01, 30_000.0), 6),
        "bwd_iat_tot": round(random.uniform(10.0, 800_000.0), 6),
        "bwd_iat_max": round(random.uniform(1.0, 250_000.0), 6),
        "bwd_iat_min": round(random.uniform(0.0, 2_000.0), 6),
        "bwd_iat_mean": round(random.uniform(0.1, 80_000.0), 6),
        "bwd_iat_std": round(random.uniform(0.01, 30_000.0), 6),
        "fwd_psh_flags": random.randint(0, 1),
        "bwd_psh_flags": random.randint(0, 1),
        "fwd_urg_flags": random.randint(0, 1),
        "bwd_urg_flags": random.randint(0, 1),
        "fin_flag_cnt": random.randint(0, 4),
        "syn_flag_cnt": random.randint(0, 4),
        "rst_flag_cnt": random.randint(0, 4),
        "psh_flag_cnt": random.randint(0, 6),
        "ack_flag_cnt": random.randint(0, 12),
        "urg_flag_cnt": random.randint(0, 3),
        "ece_flag_cnt": random.randint(0, 3),
        "down_up_ratio": round(random.uniform(0.05, 8.0), 6),
        "pkt_size_avg": round(random.uniform(30.0, 1200.0), 6),
        "init_fwd_win_byts": random.randint(0, 65535),
        "init_bwd_win_byts": random.randint(0, 65535),
        "active_max": round(random.uniform(10.0, 300_000.0), 6),
        "active_min": round(random.uniform(0.1, 20_000.0), 6),
        "active_mean": round(random.uniform(1.0, 100_000.0), 6),
        "active_std": round(random.uniform(0.01, 40_000.0), 6),
        "idle_max": round(random.uniform(10.0, 2_000_000.0), 6),
        "idle_min": round(random.uniform(0.1, 50_000.0), 6),
        "idle_mean": round(random.uniform(1.0, 600_000.0), 6),
        "idle_std": round(random.uniform(0.01, 250_000.0), 6),
        "fwd_byts_b_avg": round(random.uniform(0.0, 100_000.0), 6),
        "fwd_pkts_b_avg": round(random.uniform(0.0, 20_000.0), 6),
        "bwd_byts_b_avg": round(random.uniform(0.0, 100_000.0), 6),
        "bwd_pkts_b_avg": round(random.uniform(0.0, 20_000.0), 6),
        "fwd_blk_rate_avg": round(random.uniform(0.0, 60_000.0), 6),
        "bwd_blk_rate_avg": round(random.uniform(0.0, 60_000.0), 6),
        "fwd_seg_size_avg": round(random.uniform(20.0, 1300.0), 6),
        "bwd_seg_size_avg": round(random.uniform(20.0, 1300.0), 6),
        "cwr_flag_count": random.randint(0, 1),
        "subflow_fwd_pkts": fwd_pkts,
        "subflow_bwd_pkts": bwd_pkts,
        "subflow_fwd_byts": fwd_bytes,
        "subflow_bwd_byts": bwd_bytes,
    }
    return row


def severity_factor(severity: str) -> float:
    if severity == "critical":
        return random.uniform(2.8, 4.2)
    if severity == "high":
        return random.uniform(1.6, 2.6)
    return random.uniform(1.0, 1.5)  # medium


def apply_attack_profile(row: Dict[str, float], attack: str, severity: str) -> None:
    f = severity_factor(severity)
    dur = int(max(50, row["flow_duration"] / random.uniform(1.0, 2.2 * f)))
    row["flow_duration"] = dur

    if attack == "DDoS":
        row["protocol"] = random.choice([6, 17])
        row["dst_port"] = random.choice([53, 80, 443])
        row["tot_fwd_pkts"] = int(random.randint(300, 2500) * f)
        row["tot_bwd_pkts"] = random.randint(0, max(1, int(20 / f)))
        row["syn_flag_cnt"] = random.randint(6, int(40 * f))
        row["ack_flag_cnt"] = random.randint(0, 2)
    elif attack == "PortScan":
        row["protocol"] = 6
        row["dst_port"] = random.randint(1, 65535)
        row["tot_fwd_pkts"] = int(random.randint(40, 500) * f)
        row["tot_bwd_pkts"] = random.randint(0, max(1, int(10 / f)))
        row["syn_flag_cnt"] = random.randint(3, int(24 * f))
        row["rst_flag_cnt"] = random.randint(2, int(20 * f))
    elif attack == "BruteForce":
        row["protocol"] = 6
        row["dst_port"] = random.choice([21, 22, 23, 3389, 5900])
        row["tot_fwd_pkts"] = int(random.randint(50, 700) * f)
        row["tot_bwd_pkts"] = int(random.randint(5, 280) * (f / 1.6))
        row["syn_flag_cnt"] = random.randint(3, int(30 * f))
        row["psh_flag_cnt"] = random.randint(1, int(16 * f))
    elif attack == "Web Attack":
        row["protocol"] = random.choice([6, 17])
        row["dst_port"] = random.choice([80, 443, 8080, 8443])
        row["tot_fwd_pkts"] = int(random.randint(25, 450) * f)
        row["tot_bwd_pkts"] = int(random.randint(8, 380) * (f / 1.5))
        row["psh_flag_cnt"] = random.randint(1, int(10 * f))
        row["urg_flag_cnt"] = random.randint(0, int(2 * f))
    elif attack == "Bot":
        row["protocol"] = random.choice([6, 17])
        row["dst_port"] = random.choice([53, 80, 443, 6667, 8080, 4444])
        row["tot_fwd_pkts"] = int(random.randint(30, 900) * f)
        row["tot_bwd_pkts"] = int(random.randint(8, 320) * (f / 1.7))
        row["ack_flag_cnt"] = random.randint(4, int(18 * f))
        row["psh_flag_cnt"] = random.randint(1, int(14 * f))
    elif attack == "Infiltration":
        row["protocol"] = 6
        row["dst_port"] = random.choice([22, 23, 445, 3389, 8080, 5900])
        row["tot_fwd_pkts"] = int(random.randint(80, 1100) * f)
        row["tot_bwd_pkts"] = int(random.randint(20, 900) * (f / 1.4))
        row["ack_flag_cnt"] = random.randint(5, int(30 * f))
        row["ece_flag_cnt"] = random.randint(0, int(4 * f))
    elif attack == "Heartbleed":
        row["protocol"] = 6
        row["dst_port"] = 443
        row["tot_fwd_pkts"] = int(random.randint(25, 350) * f)
        row["tot_bwd_pkts"] = int(random.randint(5, 220) * (f / 1.7))
        row["fwd_pkt_len_max"] = int(random.randint(800, 1500) * f)
        row["bwd_pkt_len_max"] = int(random.randint(700, 1500) * f)
    else:  # Anomaly (generic outlier)
        row["protocol"] = random.choice(PROTO_POOL)
        row["dst_port"] = random.choice(COMMON_PORTS + [random.randint(1, 65535)])
        row["tot_fwd_pkts"] = int(random.randint(20, 600) * f)
        row["tot_bwd_pkts"] = int(random.randint(0, 400) * (f / 1.8))

    # Derived high-variance behavior used by the detector.
    total_pkts = max(1, row["tot_fwd_pkts"] + row["tot_bwd_pkts"])
    row["totlen_fwd_pkts"] = int(max(1, row["tot_fwd_pkts"] * random.uniform(40.0, 1800.0)))
    row["totlen_bwd_pkts"] = int(max(0, row["tot_bwd_pkts"] * random.uniform(40.0, 1800.0)))
    total_bytes = max(1, row["totlen_fwd_pkts"] + row["totlen_bwd_pkts"])
    row["flow_byts_s"] = round(rate(total_bytes, row["flow_duration"]) * random.uniform(0.8, f * 3.0), 6)
    row["flow_pkts_s"] = round(rate(total_pkts, row["flow_duration"]) * random.uniform(0.8, f * 2.8), 6)
    row["fwd_pkts_s"] = round(rate(row["tot_fwd_pkts"], row["flow_duration"]), 6)
    row["bwd_pkts_s"] = round(rate(row["tot_bwd_pkts"], row["flow_duration"]), 6)
    row["flow_iat_std"] = round(random.uniform(100.0, 900_000.0 * f), 6)
    row["fwd_iat_std"] = round(random.uniform(80.0, 500_000.0 * f), 6)
    row["bwd_iat_std"] = round(random.uniform(80.0, 500_000.0 * f), 6)
    row["pkt_len_std"] = round(random.uniform(80.0, 9_000.0 * f), 6)
    row["pkt_len_var"] = round(random.uniform(20_000.0, 500_000_000.0 * f), 6)
    row["active_max"] = round(random.uniform(10_000.0, 12_000_000.0 * f), 6)
    row["idle_std"] = round(random.uniform(1_000.0, 15_000_000.0 * f), 6)
    row["down_up_ratio"] = round(random.uniform(0.1, 250.0 * f), 6)
    row["subflow_fwd_pkts"] = row["tot_fwd_pkts"]
    row["subflow_bwd_pkts"] = row["tot_bwd_pkts"]
    row["subflow_fwd_byts"] = row["totlen_fwd_pkts"]
    row["subflow_bwd_byts"] = row["totlen_bwd_pkts"]
    row["pkt_size_avg"] = round(clamp(total_bytes / total_pkts, 20.0, 1600.0), 6)
    row["fwd_seg_size_avg"] = round(clamp(row["totlen_fwd_pkts"] / max(1, row["tot_fwd_pkts"]), 20.0, 1600.0), 6)
    row["bwd_seg_size_avg"] = round(clamp((row["totlen_bwd_pkts"] or 0) / max(1, row["tot_bwd_pkts"] or 1), 20.0, 1600.0), 6)


def normalize_row(row: Dict[str, float]) -> List[float]:
    return [row.get(col, 0) for col in SCHEMA]


def choose_weighted(values: List[str], weights: List[float]) -> str:
    return random.choices(values, weights=weights, k=1)[0]


def random_weights(n: int, lo: float, hi: float) -> List[float]:
    vals = [random.uniform(lo, hi) for _ in range(n)]
    s = sum(vals)
    return [v / s for v in vals]


def build_class_schedule(total_rows: int, classes: List[str], weights: List[float]) -> List[str]:
    schedule = random.choices(classes, weights=weights, k=total_rows)
    # Ensure every selected class appears at least once.
    for cls in classes:
        if cls not in schedule:
            schedule[random.randint(0, total_rows - 1)] = cls
    random.shuffle(schedule)
    return schedule


def build_severity_schedule(total_attack_rows: int) -> List[str]:
    if total_attack_rows <= 0:
        return []
    # Force presence of medium/high/critical whenever possible.
    schedule = []
    base = ["medium", "high", "critical"]
    for sev in base[: min(len(base), total_attack_rows)]:
        schedule.append(sev)
    remaining = total_attack_rows - len(schedule)
    if remaining > 0:
        extra_weights = random_weights(3, 0.2, 0.8)
        schedule.extend(random.choices(SEVERITIES, weights=extra_weights, k=remaining))
    random.shuffle(schedule)
    return schedule


def generate_file(path: Path, rows: int, start_ts: datetime) -> None:
    # Choose random subset of attacks for this file (not always all).
    attack_subset = random.sample(ATTACK_TYPES, k=random.randint(4, len(ATTACK_TYPES)))
    classes = ["Benign"] + attack_subset

    class_weights = [random.uniform(0.15, 0.45)] + [random.uniform(0.06, 0.32) for _ in attack_subset]
    total_w = sum(class_weights)
    class_weights = [w / total_w for w in class_weights]

    class_schedule = build_class_schedule(rows, classes, class_weights)
    total_attack_rows = sum(1 for c in class_schedule if c != "Benign")
    severity_schedule = build_severity_schedule(total_attack_rows)
    sev_idx = 0

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(SCHEMA)
        ts = start_ts
        for cls in class_schedule:
            row = base_row(ts)
            if cls != "Benign":
                sev = severity_schedule[sev_idx]
                sev_idx += 1
                apply_attack_profile(row, cls, sev)
            writer.writerow(normalize_row(row))
            ts += timedelta(milliseconds=random.randint(1, 3000))

    medium_share = (severity_schedule.count("medium") / max(1, len(severity_schedule)))
    high_share = (severity_schedule.count("high") / max(1, len(severity_schedule)))
    critical_share = (severity_schedule.count("critical") / max(1, len(severity_schedule)))
    print(
        f"Generated: {path} | rows={rows} | classes={classes} "
        f"| class_weights={[round(w,3) for w in class_weights]} "
        f"| severity_share={{'medium':{medium_share:.3f},'high':{high_share:.3f},'critical':{critical_share:.3f}}}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate randomized Dooms'Day processed flow CSV files.")
    parser.add_argument("--files", type=int, default=10, help="Number of CSV files (max 10)")
    parser.add_argument("--min-rows", type=int, default=1800, help="Min rows per file")
    parser.add_argument("--max-rows", type=int, default=7000, help="Max rows per file")
    parser.add_argument("--seed", type=int, default=None, help="Optional fixed seed (omit for full random)")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
    else:
        random.seed()

    files = max(1, min(args.files, 10))
    min_rows = max(200, min(args.min_rows, args.max_rows))
    max_rows = max(min_rows, args.max_rows)

    out_dir = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "processed"
        / "cic_ids"
        / "flows"
        / "Dooms'Day"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    # remove prior generated doomsday files
    for old in out_dir.glob("doomsday__*.csv"):
        old.unlink()

    base_ts = datetime(2017, 7, 9, 1, 0, 0)
    current = base_ts
    for i in range(files):
        rows = random.randint(min_rows, max_rows)
        filename = f"doomsday__{i:05d}_{current.strftime('%Y%m%d%H%M%S')}.csv"
        path = out_dir / filename
        generate_file(path, rows=rows, start_ts=current)
        current += timedelta(minutes=random.randint(3, 17))

    print(f"Done. Generated {files} files in {out_dir}")


if __name__ == "__main__":
    main()
