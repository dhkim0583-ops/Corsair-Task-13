import os
import json
from stages.cctf import decode_frames, recover_committed

def _recover_committed(frames, schema_versions):
    return recover_committed(frames, schema_versions)

def recover_ledgers(data_dir: str, output_dir: str, config: dict = None) -> dict:
    config = config or {}
    schema_versions = config.get("schema_versions", {})
    os.makedirs(output_dir, exist_ok=True)
    scanners = {}
    for f in os.listdir(data_dir):
        if f.startswith("scanner_") and (f.endswith(".cctf") or f.endswith(".cctf.tmp")):
            base = f[len("scanner_"):]
            s_id = base.split(".cctf")[0]
            scanners.setdefault(s_id, []).append(f)
    audit = {}
    for s_id, f_list in scanners.items():
        all_records = []
        for f in f_list:
            with open(os.path.join(data_dir, f), "rb") as fh:
                raw = fh.read()
            all_records.extend(_recover_committed(decode_frames(raw), schema_versions))
        dedup = {}
        for r in all_records:
            tx_id = r.get("transaction_id")
            if not tx_id:
                continue
            if tx_id not in dedup or r.get("timestamp", 0) > dedup[tx_id].get("timestamp", 0):
                dedup[tx_id] = r
        recovered_list = list(dedup.values())
        with open(os.path.join(output_dir, f"recovered_{s_id}.json"), "w") as fh:
            json.dump(recovered_list, fh, indent=2)
        audit[s_id] = len(recovered_list)
    with open(os.path.join(output_dir, "audit_recovery.json"), "w") as fh:
        json.dump(audit, fh, indent=2)
    return audit
