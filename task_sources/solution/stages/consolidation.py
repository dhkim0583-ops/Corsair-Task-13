import json
import hashlib
import hmac

CHAIN_INIT = b"CCTF-ROOT-V1"
SIG_PREFIX = b"coldchain-fleet|"
HASH_FIELDS = ["transaction_id", "scanner_id", "sequence", "timestamp", "temperature_c"]

def _projection(record):
    obj = {}
    for k in HASH_FIELDS:
        if k == "temperature_c":
            obj[k] = round(record["temperature_c"], 2)
        else:
            obj[k] = record[k]
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

def consolidate_and_checksum(all_records: list, output_path: str, root_path: str, sig_path: str) -> str:
    all_records.sort(key=lambda x: (x.get("scanner_id", ""), x.get("sequence", 0), x.get("timestamp", 0)))
    with open(output_path, "w") as fh:
        json.dump(all_records, fh, indent=2)
    state = hashlib.sha256(CHAIN_INIT).digest()
    for r in all_records:
        state = hashlib.sha256(state + _projection(r)).digest()
    root = state
    n = len(all_records)
    key = hashlib.sha256(SIG_PREFIX + str(n).encode("utf-8")).digest()
    sig = hmac.new(key, root, hashlib.sha256).digest()
    with open(root_path, "wb") as fh:
        fh.write(root)
    with open(sig_path, "wb") as fh:
        fh.write(sig)
    return root.hex()
