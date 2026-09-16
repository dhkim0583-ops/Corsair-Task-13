#!/usr/bin/env python3
import argparse
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from stages.recovery import recover_ledgers
from stages.aggregation import aggregate_metrics
from stages.replay import replay_dead_letters
from stages.consolidation import consolidate_and_checksum

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def main():
    parser = argparse.ArgumentParser(description="Cold-Chain CCTF Reconciliation Pipeline")
    parser.add_argument("--config", default=os.path.join(BASE_DIR, "config/pipeline_config.json"))
    parser.add_argument("--data-dir", default=os.path.join(BASE_DIR, "data/raw"))
    parser.add_argument("--dlq-dir", default=os.path.join(BASE_DIR, "data/raw/dlq"))
    parser.add_argument("--metrics-file", default=os.path.join(BASE_DIR, "data/raw/metrics.cctf"))
    parser.add_argument("--output-dir", default=os.path.join(BASE_DIR, "data/processed"))
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    with open(args.config, "r") as fh:
        config = json.load(fh)

    recover_ledgers(args.data_dir, args.output_dir, config)

    aggregated = aggregate_metrics(args.metrics_file, config)
    with open(os.path.join(args.output_dir, "aggregated_metrics.json"), "w") as fh:
        json.dump(aggregated, fh, indent=2)

    combined, audit_rep = replay_dead_letters(args.output_dir, args.dlq_dir, config)
    with open(os.path.join(args.output_dir, "audit_replay.json"), "w") as fh:
        json.dump(audit_rep, fh, indent=2)

    ledger_out = os.path.join(args.output_dir, "consolidated_ledger.json")
    root_out = os.path.join(args.output_dir, "ledger_root.bin")
    sig_out = os.path.join(args.output_dir, "ledger_signature.bin")
    chk = consolidate_and_checksum(combined, ledger_out, root_out, sig_out)
    print(f"Pipeline completed. Root: {chk}")

if __name__ == "__main__":
    main()
