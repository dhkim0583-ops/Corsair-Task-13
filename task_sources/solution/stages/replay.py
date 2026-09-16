import os
import json
from stages.cctf import decode_frames, recover_committed

def _recover_committed(frames, schema_versions):
    return recover_committed(frames, schema_versions)

def replay_dead_letters(recovered_dir: str, dlq_dir: str, config: dict) -> tuple:
    lock_timeout = config.get("lock_timeout_sec", 60)
    schema_versions = config.get("schema_versions", {})
    recovered_records = {}
    for f in os.listdir(recovered_dir):
        if f.startswith("recovered_") and f.endswith(".json"):
            with open(os.path.join(recovered_dir, f), "r") as fh:
                for r in json.load(fh):
                    tx_id = r.get("transaction_id")
                    if tx_id:
                        recovered_records[tx_id] = r
    integrated_count = 0
    duplicate_count = 0
    if os.path.exists(dlq_dir):
        for f in sorted(os.listdir(dlq_dir)):
            if f.endswith(".cctf"):
                with open(os.path.join(dlq_dir, f), "rb") as fh:
                    raw = fh.read()
                for dlq_r in _recover_committed(decode_frames(raw), schema_versions):
                    tx_id = dlq_r.get("transaction_id")
                    if not tx_id:
                        continue
                    if tx_id in recovered_records:
                        diff = abs(dlq_r.get("timestamp", 0) - recovered_records[tx_id].get("timestamp", 0))
                        if diff <= lock_timeout:
                            duplicate_count += 1
                        else:
                            recovered_records[tx_id] = dlq_r
                            integrated_count += 1
                    else:
                        recovered_records[tx_id] = dlq_r
                        integrated_count += 1
    audit = {"integrated_dlq_records": integrated_count, "discarded_duplicates": duplicate_count}
    return list(recovered_records.values()), audit
