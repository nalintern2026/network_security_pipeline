#!/usr/bin/env python3
"""
Convert CIC IDS pcap chunks to CSV flows using CICFlowMeter.
Reads from data/raw/cic_ids/pcap_chunks/<day>/ and writes to data/processed/cic_ids/flows/<day>/.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

NAL_ROOT = Path(__file__).resolve().parent.parent
PCAP_CHUNKS = NAL_ROOT / "data" / "raw" / "cic_ids" / "pcap_chunks"
FLOWS_OUT = NAL_ROOT / "data" / "processed" / "cic_ids" / "flows"
CICFLOWMETER = NAL_ROOT / ".venv" / "bin" / "cicflowmeter"

DAYS = ("friday", "monday", "thursday", "tuesday", "wednesday")


def main() -> int:
    if not CICFLOWMETER.exists():
        print("CICFlowMeter not found. Create venv and install: python -m venv .venv && .venv/bin/pip install cicflowmeter", file=sys.stderr)
        return 1
    if not PCAP_CHUNKS.exists():
        print(f"Pcap chunks dir not found: {PCAP_CHUNKS}", file=sys.stderr)
        return 1

    FLOWS_OUT.mkdir(parents=True, exist_ok=True)

    for day in DAYS:
        inp = PCAP_CHUNKS / day
        out_dir = FLOWS_OUT / day
        if not inp.exists() or not inp.is_dir():
            print(f"Skipping {day}: not found")
            continue
        pcap_files = sorted(f for f in inp.iterdir() if f.is_file())
        out_dir.mkdir(parents=True, exist_ok=True)
        done = 0
        for i, pcap_file in enumerate(pcap_files, 1):
            csv_path = out_dir / f"{pcap_file.name}.csv"
            if csv_path.exists():
                done += 1
                continue
            print(f"[{day}] {i}/{len(pcap_files)} {pcap_file.name}")
            r = subprocess.run(
                [str(CICFLOWMETER), "-f", str(pcap_file), "-c", str(csv_path)],
                cwd=NAL_ROOT,
            )
            if r.returncode != 0:
                print(f"cicflowmeter failed for {pcap_file.name} (exit {r.returncode})", file=sys.stderr)
                return r.returncode
            done += 1
        print(f"Completed {day}: {done} files")
    print("Done. CSVs saved under data/processed/cic_ids/flows/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
