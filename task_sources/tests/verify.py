import os
import json
import struct
import zlib
import hashlib
import hmac
import re
import sys
import subprocess

MAGIC = b"CC"
F_TXN = 1
F_METRIC = 2
F_COMMIT = 3
F_ABORT = 4
F_SAVEPOINT = 5
F_ROLLBACK = 6

CHAIN_INIT = b"CCTF-ROOT-V1"
SIG_PREFIX = b"coldchain-fleet|"
HASH_FIELDS = ["transaction_id", "scanner_id", "sequence", "timestamp", "temperature_c"]


def decode_frames(raw):
    frames = []
    off = 0
    n = len(raw)
    prev_chain = 0
    while off < n:
        if n - off < 10:
            break
        if raw[off:off + 2] != MAGIC:
            break
        version = raw[off + 2]
        ftype = raw[off + 3]
        seq = struct.unpack(">I", raw[off + 4:off + 8])[0]
        plen = struct.unpack(">H", raw[off + 8:off + 10])[0]
        frame_end = off + 10 + plen + 8
        if frame_end > n:
            break
        body = raw[off:off + 10 + plen]
        crc_stored = struct.unpack(">I", raw[off + 10 + plen:off + 10 + plen + 4])[0]
        if (zlib.crc32(body) & 0xFFFFFFFF) != crc_stored:
            break
        chain_stored = struct.unpack(">I", raw[off + 10 + plen + 4:frame_end])[0]
        chain_calc = zlib.crc32(struct.pack(">I", prev_chain) + struct.pack(">I", crc_stored)) & 0xFFFFFFFF
        if chain_calc != chain_stored:
            break
        frames.append((version, ftype, seq, raw[off + 10:off + 10 + plen]))
        prev_chain = chain_stored
        off = frame_end
    return frames


def _migrate(rec, version, schema_versions):
    entry = schema_versions.get(str(version), {})
    field = entry.get("temperature_field", "temperature_c")
    scale = entry.get("scale", "celsius")
    if field in rec:
        val = rec[field]
        if field != "temperature_c":
            del rec[field]
        rec["temperature_c"] = (val / 10.0) if scale == "deci_celsius" else val
    return rec


def recover_committed(frames, schema_versions):
    committed = []
    pending = []
    savepoints = {}
    for version, ftype, seq, payload in frames:
        if ftype == F_TXN:
            rec = json.loads(payload.decode("utf-8"))
            _migrate(rec, version, schema_versions)
            pending.append(rec)
        elif ftype == F_SAVEPOINT:
            name = json.loads(payload.decode("utf-8"))["savepoint"]
            savepoints[name] = len(pending)
        elif ftype == F_ROLLBACK:
            name = json.loads(payload.decode("utf-8"))["savepoint"]
            if name in savepoints:
                target = savepoints[name]
                del pending[target:]
                savepoints = {k: v for k, v in savepoints.items() if v <= target}
        elif ftype == F_COMMIT:
            committed.extend(pending)
            pending = []
            savepoints = {}
        elif ftype == F_ABORT:
            pending = []
            savepoints = {}
    return committed


def get_reference_recovery(data_dir, config):
    schema_versions = config.get("schema_versions", {})
    files = os.listdir(data_dir)
    scanners = {}
    for f in files:
        if f.startswith("scanner_") and (f.endswith(".cctf") or f.endswith(".cctf.tmp")):
            base = f[len("scanner_"):]
            s_id = base.split(".cctf")[0]
            scanners.setdefault(s_id, []).append(f)
    ref_audit = {}
    ref_records_by_scanner = {}
    for s_id, f_list in scanners.items():
        all_records = []
        for f in f_list:
            with open(os.path.join(data_dir, f), "rb") as fh:
                raw = fh.read()
            all_records.extend(recover_committed(decode_frames(raw), schema_versions))
        dedup = {}
        for r in all_records:
            tx_id = r.get("transaction_id")
            if not tx_id:
                continue
            if tx_id not in dedup or r.get("timestamp", 0) > dedup[tx_id].get("timestamp", 0):
                dedup[tx_id] = r
        ref_records_by_scanner[s_id] = list(dedup.values())
        ref_audit[s_id] = len(ref_records_by_scanner[s_id])
    return ref_audit, ref_records_by_scanner


def get_reference_aggregation(metrics_file, config):
    if not os.path.exists(metrics_file):
        return []
    with open(metrics_file, "rb") as fh:
        raw = fh.read()
    metrics = [json.loads(p.decode("utf-8")) for (v, t, s, p) in decode_frames(raw) if t == F_METRIC]
    metric_cfg = config.get("metric_config", {})
    whitelist = set(metric_cfg.get("whitelisted_attributes", []))
    interval = metric_cfg.get("aggregation_interval_hours", 1) * 3600
    groups = {}
    for m in metrics:
        name = m.get("metric_name")
        ts = m.get("timestamp")
        val = m.get("value")
        attrs = m.get("attributes", {})
        if ts is None or val is None or name is None:
            continue
        bucket = ts - (ts % interval)
        filtered_attrs = {k: v for k, v in attrs.items() if k in whitelist}
        group_key = (name, bucket, frozenset(filtered_attrs.items()))
        groups.setdefault(group_key, []).append(val)
    aggregated = []
    for (name, bucket, attrs_fs), vals in groups.items():
        mean_val = sum(vals) / len(vals)
        aggregated.append({
            "metric_name": name,
            "timestamp": bucket,
            "value": round(mean_val, 4),
            "attributes": dict(attrs_fs),
        })
    aggregated.sort(key=lambda x: (x["metric_name"], x["timestamp"], json.dumps(x["attributes"], sort_keys=True)))
    return aggregated


def get_reference_replay(recovered_records_by_scanner, dlq_dir, config):
    lock_timeout = config.get("lock_timeout_sec", 60)
    schema_versions = config.get("schema_versions", {})
    recovered_records = {}
    for s_id, r_list in recovered_records_by_scanner.items():
        for r in r_list:
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
                for dlq_r in recover_committed(decode_frames(raw), schema_versions):
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
    ref_audit = {"integrated_dlq_records": integrated_count, "discarded_duplicates": duplicate_count}
    return list(recovered_records.values()), ref_audit


def _projection(record):
    obj = {}
    for k in HASH_FIELDS:
        if k == "temperature_c":
            obj[k] = round(record["temperature_c"], 2)
        else:
            obj[k] = record[k]
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def get_reference_consolidation(all_records):
    all_records.sort(key=lambda x: (x.get("scanner_id", ""), x.get("sequence", 0), x.get("timestamp", 0)))
    state = hashlib.sha256(CHAIN_INIT).digest()
    for r in all_records:
        state = hashlib.sha256(state + _projection(r)).digest()
    root = state
    n = len(all_records)
    key = hashlib.sha256(SIG_PREFIX + str(n).encode("utf-8")).digest()
    sig = hmac.new(key, root, hashlib.sha256).digest()
    return all_records, root, sig


def _load_config(config_file):
    with open(config_file, "r") as fh:
        return json.load(fh)


def verify_stage1(output_dir, data_dir, config_file):
    config = _load_config(config_file)
    audit_path = os.path.join(output_dir, "audit_recovery.json")
    if not os.path.exists(audit_path):
        print("ERROR: audit_recovery.json not found")
        return False
    with open(audit_path, "r") as fh:
        agent_audit = json.load(fh)
    ref_audit, ref_records = get_reference_recovery(data_dir, config)
    if agent_audit != ref_audit:
        print(f"ERROR: Stage 1 audit mismatch. Expected {ref_audit}, got {agent_audit}")
        return False
    for s_id, expected_count in ref_audit.items():
        agent_file = os.path.join(output_dir, f"recovered_{s_id}.json")
        if not os.path.exists(agent_file):
            print(f"ERROR: recovered_{s_id}.json not found")
            return False
        with open(agent_file, "r") as fh:
            agent_records = json.load(fh)
        if len(agent_records) != expected_count:
            print(f"ERROR: Record count mismatch for {s_id}. Expected {expected_count}, got {len(agent_records)}")
            return False
        agent_txs = {r["transaction_id"]: r for r in agent_records}
        ref_txs = {r["transaction_id"]: r for r in ref_records[s_id]}
        if agent_txs.keys() != ref_txs.keys():
            print(f"ERROR: Recovered transaction IDs mismatch for {s_id}")
            return False
        for tx_id, ref_r in ref_txs.items():
            if agent_txs[tx_id] != ref_r:
                print(f"ERROR: Recovered record content mismatch for {s_id}/{tx_id}. Expected {ref_r}, got {agent_txs[tx_id]}")
                return False
    print("STAGE 1 OK")
    return True


def verify_stage2(output_dir, metrics_file, config_file):
    config = _load_config(config_file)
    ref_agg = get_reference_aggregation(metrics_file, config)
    agent_agg_file = os.path.join(output_dir, "aggregated_metrics.json")
    if not os.path.exists(agent_agg_file):
        print("ERROR: aggregated_metrics.json not found")
        return False
    with open(agent_agg_file, "r") as fh:
        agent_agg = json.load(fh)
    if len(agent_agg) != len(ref_agg):
        print(f"ERROR: Metric counts mismatch. Expected {len(ref_agg)}, got {len(agent_agg)}")
        return False
    for a_m, r_m in zip(agent_agg, ref_agg):
        if a_m["metric_name"] != r_m["metric_name"] or a_m["timestamp"] != r_m["timestamp"]:
            print("ERROR: Mismatch in metric names or timestamps")
            return False
        if abs(a_m["value"] - r_m["value"]) > 1e-3:
            print(f"ERROR: Value mismatch. Expected {r_m['value']}, got {a_m['value']}")
            return False
        if a_m["attributes"] != r_m["attributes"]:
            print("ERROR: Attribute filter mismatch")
            return False
    print("STAGE 2 OK")
    return True


def verify_stage3(output_dir, data_dir, dlq_dir, config_file):
    config = _load_config(config_file)
    _, ref_records = get_reference_recovery(data_dir, config)
    _, ref_audit = get_reference_replay(ref_records, dlq_dir, config)
    agent_audit_file = os.path.join(output_dir, "audit_replay.json")
    if not os.path.exists(agent_audit_file):
        print("ERROR: audit_replay.json not found")
        return False
    with open(agent_audit_file, "r") as fh:
        agent_audit = json.load(fh)
    if agent_audit != ref_audit:
        print(f"ERROR: Stage 3 audit mismatch. Expected {ref_audit}, got {agent_audit}")
        return False
    print("STAGE 3 OK")
    return True


def verify_stage4_and_checksum(output_dir, data_dir, dlq_dir, config_file):
    config = _load_config(config_file)
    _, ref_records_by_scanner = get_reference_recovery(data_dir, config)
    ref_all_records, _ = get_reference_replay(ref_records_by_scanner, dlq_dir, config)
    ref_consolidated, ref_root, ref_sig = get_reference_consolidation(ref_all_records)
    agent_ledger_file = os.path.join(output_dir, "consolidated_ledger.json")
    agent_root_file = os.path.join(output_dir, "ledger_root.bin")
    agent_sig_file = os.path.join(output_dir, "ledger_signature.bin")
    for p, label in [(agent_ledger_file, "consolidated_ledger.json"),
                     (agent_root_file, "ledger_root.bin"),
                     (agent_sig_file, "ledger_signature.bin")]:
        if not os.path.exists(p):
            print(f"ERROR: {label} not found")
            return False
    with open(agent_ledger_file, "r") as fh:
        agent_ledger = json.load(fh)
    with open(agent_root_file, "rb") as fh:
        agent_root = fh.read()
    with open(agent_sig_file, "rb") as fh:
        agent_sig = fh.read()
    if len(agent_ledger) != len(ref_consolidated):
        print(f"ERROR: Consolidated ledger size mismatch. Expected {len(ref_consolidated)}, got {len(agent_ledger)}")
        return False
    for i, (a_r, r_r) in enumerate(zip(agent_ledger, ref_consolidated)):
        if a_r != r_r:
            print(f"ERROR: Record mismatch at index {i}. Expected {r_r}, got {a_r}")
            return False
    if agent_root != ref_root:
        print(f"ERROR: Chain root mismatch. Expected {ref_root.hex()}, got {agent_root.hex()}")
        return False
    if agent_sig != ref_sig:
        print(f"ERROR: Signature mismatch. Expected {ref_sig.hex()}, got {agent_sig.hex()}")
        return False
    print("STAGE 4 AND CHECKSUM OK")
    return True


def verify_mutated_run(workspace_dir):
    raw_dir = os.path.join(workspace_dir, "data/raw_mutated")
    proc_dir = os.path.join(workspace_dir, "data/processed_mutated")
    config_file = os.path.join(workspace_dir, "config/pipeline_config.json")
    metrics_file = os.path.join(raw_dir, "metrics.cctf")
    dlq_dir = os.path.join(raw_dir, "dlq")
    gen = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generate_test_data.py")
    cmd_gen = f"python3 {gen} --data-dir {raw_dir} --seed 99"
    res_gen = subprocess.run(cmd_gen, shell=True, capture_output=True, text=True)
    if res_gen.returncode != 0:
        print(f"ERROR: Mutation generator failed: {res_gen.stderr}")
        return False
    cmd_pipe = (f"python3 {workspace_dir}/recon_pipeline.py --config {config_file} "
                f"--data-dir {raw_dir} --dlq-dir {dlq_dir} --metrics-file {metrics_file} --output-dir {proc_dir}")
    res_pipe = subprocess.run(cmd_pipe, shell=True, capture_output=True, text=True)
    if res_pipe.returncode != 0:
        print(f"ERROR: Agent's pipeline failed on mutated data: {res_pipe.stderr}")
        return False
    if not verify_stage1(proc_dir, raw_dir, config_file):
        return False
    if not verify_stage2(proc_dir, metrics_file, config_file):
        return False
    if not verify_stage3(proc_dir, raw_dir, dlq_dir, config_file):
        return False
    if not verify_stage4_and_checksum(proc_dir, raw_dir, dlq_dir, config_file):
        return False
    print("MUTATED RUN OK")
    return True


def verify_anti_shortcut(workspace_dir):
    stages_dir = os.path.join(workspace_dir, "stages")
    targets = []
    for root, dirs, files in os.walk(stages_dir):
        for f in files:
            if f.endswith(".py"):
                targets.append(os.path.join(root, f))
    pipeline = os.path.join(workspace_dir, "recon_pipeline.py")
    if os.path.exists(pipeline):
        targets.append(pipeline)
    for path in targets:
        with open(path, "r", errors="ignore") as fh:
            content = fh.read()
        if re.search(r'["\'][0-9a-fA-F]{64}["\']', content):
            print(f"ERROR: Hardcoded 64-hex digest literal detected in {os.path.basename(path)}!")
            return False
        if re.search(r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}', content):
            print(f"ERROR: Hardcoded raw byte digest literal detected in {os.path.basename(path)}!")
            return False
    print("ANTI-SHORTCUT OK")
    return True


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", type=int)
    parser.add_argument("--mutated", action="store_true")
    parser.add_argument("--anti-shortcut", action="store_true")
    args = parser.parse_args()
    workspace = "/workspace/coldchain-recon"
    data_dir = os.path.join(workspace, "data/raw")
    dlq_dir = os.path.join(workspace, "data/raw/dlq")
    metrics_file = os.path.join(workspace, "data/raw/metrics.cctf")
    output_dir = os.path.join(workspace, "data/processed")
    config_file = os.path.join(workspace, "config/pipeline_config.json")
    if args.stage == 1:
        sys.exit(0 if verify_stage1(output_dir, data_dir, config_file) else 1)
    elif args.stage == 2:
        sys.exit(0 if verify_stage2(output_dir, metrics_file, config_file) else 1)
    elif args.stage == 3:
        sys.exit(0 if verify_stage3(output_dir, data_dir, dlq_dir, config_file) else 1)
    elif args.stage == 4:
        sys.exit(0 if verify_stage4_and_checksum(output_dir, data_dir, dlq_dir, config_file) else 1)
    elif args.mutated:
        sys.exit(0 if verify_mutated_run(workspace) else 1)
    elif args.anti_shortcut:
        sys.exit(0 if verify_anti_shortcut(workspace) else 1)
    else:
        print("No action specified")
        sys.exit(1)


if __name__ == "__main__":
    main()
