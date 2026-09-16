import os
import json
import struct
import zlib
import hashlib
import hmac
import random
import sys

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

SCHEMA_VERSIONS = {
    "1": {"temperature_field": "temp", "scale": "celsius"},
    "2": {"temperature_field": "temperature_c", "scale": "celsius"},
    "3": {"temperature_field": "temp_dc", "scale": "deci_celsius"},
}


class Stream:
    """Builds a CCTF stream, threading the per-frame chain link through frames."""

    def __init__(self):
        self.buf = b""
        self.prev_chain = 0

    def frame_bytes(self, version, ftype, seq, payload=b""):
        head = MAGIC + struct.pack(">BB", version, ftype) + struct.pack(">I", seq) + struct.pack(">H", len(payload))
        body = head + payload
        crc = zlib.crc32(body) & 0xFFFFFFFF
        chain = zlib.crc32(struct.pack(">I", self.prev_chain) + struct.pack(">I", crc)) & 0xFFFFFFFF
        return body + struct.pack(">I", crc) + struct.pack(">I", chain), crc, chain

    def add(self, version, ftype, seq, payload=b""):
        frame, crc, chain = self.frame_bytes(version, ftype, seq, payload)
        self.prev_chain = chain
        self.buf += frame
        return frame


def txn_payload(version, tx_id, scanner_id, seq, ts, temp, battery):
    if version == 1:
        rec = {"transaction_id": tx_id, "scanner_id": scanner_id, "sequence": seq,
               "timestamp": ts, "temp": temp, "battery_level": battery}
    elif version == 2:
        rec = {"transaction_id": tx_id, "scanner_id": scanner_id, "sequence": seq,
               "timestamp": ts, "temperature_c": temp, "battery_level": battery, "fw": "fw_2.3.1"}
    else:
        rec = {"transaction_id": tx_id, "scanner_id": scanner_id, "sequence": seq,
               "timestamp": ts, "temp_dc": int(round(temp * 10)), "battery_level": battery, "fw": "fw_3.1.0"}
    return json.dumps(rec, separators=(",", ":")).encode("utf-8")


def sp_payload(name):
    return json.dumps({"savepoint": name}, separators=(",", ":")).encode("utf-8")


def metric_payload(rec):
    return json.dumps(rec, separators=(",", ":")).encode("utf-8")


def _temp(s_idx, seq):
    return round(-20.0 + (seq % 10) * 0.5 + s_idx * 0.2 + seq * 0.0137, 4)


def _temp_v3(s_idx, seq):
    # one-decimal Celsius so the deci-Celsius integer round-trips exactly
    return round(-20.0 + (seq % 10) * 0.5 + s_idx * 0.2, 1)


def _canon_temp(version, temp):
    if version == 3:
        return int(round(temp * 10)) / 10.0
    return temp


def _build_scanner_files(data_dir, seed):
    start_ts = 1717200000 + seed * 3
    tx_map = {}

    def reg(tx_id, scanner_id, seq, ts, temp, battery, version):
        norm = {"transaction_id": tx_id, "scanner_id": scanner_id, "sequence": seq,
                "timestamp": ts, "temperature_c": _canon_temp(version, temp), "battery_level": battery}
        if version in (2, 3):
            norm["fw"] = "fw_2.3.1" if version == 2 else "fw_3.1.0"
        tx_map[tx_id] = norm

    # scan_001: clean v3 firmware (integer deci-Celsius temperatures), all committed,
    # txns in commit epochs of 10.
    s = Stream()
    n1 = 40 + (seed % 5)
    for seq in range(1, n1 + 1):
        tx_id = f"tx_scan_001_{seq:03d}"
        ts = start_ts + seq * 10
        temp = _temp_v3(0, seq)
        s.add(3, F_TXN, seq, txn_payload(3, tx_id, "scan_001", seq, ts, temp, max(40, 100 - seq)))
        reg(tx_id, "scan_001", seq, ts, temp, max(40, 100 - seq), 3)
        if seq % 10 == 0:
            s.add(3, F_COMMIT, seq)
    if n1 % 10 != 0:
        s.add(3, F_COMMIT, n1)
    with open(os.path.join(data_dir, "scanner_scan_001.cctf"), "wb") as fh:
        fh.write(s.buf)

    # scan_002: v2, 25 committed then 5 uncommitted tail with truncated trailing COMMIT.
    s = Stream()
    for seq in range(1, 26):
        tx_id = f"tx_scan_002_{seq:03d}"
        ts = start_ts + seq * 10
        temp = _temp(1, seq)
        s.add(2, F_TXN, seq, txn_payload(2, tx_id, "scan_002", seq, ts, temp, max(40, 100 - seq)))
        reg(tx_id, "scan_002", seq, ts, temp, max(40, 100 - seq), 2)
    s.add(2, F_COMMIT, 25)
    for seq in range(26, 31):
        tx_id = f"tx_scan_002_{seq:03d}"
        ts = start_ts + seq * 10
        s.add(2, F_TXN, seq, txn_payload(2, tx_id, "scan_002", seq, ts, _temp(1, seq), max(40, 100 - seq)))
    trailing_commit, _, _ = s.frame_bytes(2, F_COMMIT, 30)
    buf = s.buf + trailing_commit[:-3]  # truncate the final COMMIT frame (power cut)
    with open(os.path.join(data_dir, "scanner_scan_002.cctf"), "wb") as fh:
        fh.write(buf)

    # scan_003: rename gap, v1 both files. .cctf has 15 (lower ts), .cctf.tmp has 20 (higher ts).
    s = Stream()
    for seq in range(1, 16):
        tx_id = f"tx_scan_003_{seq:03d}"
        ts = start_ts + seq * 10
        s.add(1, F_TXN, seq, txn_payload(1, tx_id, "scan_003", seq, ts, _temp(2, seq), max(40, 100 - seq)))
    s.add(1, F_COMMIT, 15)
    buf_main = s.buf + b"\x43\x43\x01\x01\x00\x00"  # corrupt tail (incomplete trailing bytes)
    with open(os.path.join(data_dir, "scanner_scan_003.cctf"), "wb") as fh:
        fh.write(buf_main)

    s = Stream()
    for seq in range(1, 21):
        tx_id = f"tx_scan_003_{seq:03d}"
        ts = start_ts + seq * 10 + 5  # higher timestamp => wins dedup
        temp = _temp(2, seq)
        s.add(1, F_TXN, seq, txn_payload(1, tx_id, "scan_003", seq, ts, temp, max(40, 100 - seq)))
        reg(tx_id, "scan_003", seq, ts, temp, max(40, 100 - seq), 1)
    s.add(1, F_COMMIT, 20)
    with open(os.path.join(data_dir, "scanner_scan_003.cctf.tmp"), "wb") as fh:
        fh.write(s.buf)

    # scan_004: v2, 12 committed, then 6 more TXN followed by a COMMIT whose CHAIN link is
    # corrupted (its own CRC stays valid). The chain break is the corruption boundary, so the
    # 6 trailing TXNs are never committed -> 12 recovered. A decoder that skips chain
    # validation would wrongly commit 18.
    s = Stream()
    for seq in range(1, 13):
        tx_id = f"tx_scan_004_{seq:03d}"
        ts = start_ts + seq * 10
        temp = _temp(3, seq)
        s.add(2, F_TXN, seq, txn_payload(2, tx_id, "scan_004", seq, ts, temp, max(40, 100 - seq)))
        reg(tx_id, "scan_004", seq, ts, temp, max(40, 100 - seq), 2)
    s.add(2, F_COMMIT, 12)
    for seq in range(13, 19):
        tx_id = f"tx_scan_004_{seq:03d}"
        ts = start_ts + seq * 10
        s.add(2, F_TXN, seq, txn_payload(2, tx_id, "scan_004", seq, ts, _temp(3, seq), max(40, 100 - seq)))
    bad_commit, _, _ = s.frame_bytes(2, F_COMMIT, 18)
    bad = bytearray(bad_commit)
    bad[-1] ^= 0xFF  # corrupt the trailing chain link (CRC remains valid)
    buf = s.buf + bytes(bad)
    with open(os.path.join(data_dir, "scanner_scan_004.cctf"), "wb") as fh:
        fh.write(buf)

    # scan_005: v1, clean, 30 committed (some receive DLQ corrections).
    s = Stream()
    for seq in range(1, 31):
        tx_id = f"tx_scan_005_{seq:03d}"
        ts = start_ts + seq * 10
        temp = _temp(4, seq)
        s.add(1, F_TXN, seq, txn_payload(1, tx_id, "scan_005", seq, ts, temp, max(40, 100 - seq)))
        reg(tx_id, "scan_005", seq, ts, temp, max(40, 100 - seq), 1)
    s.add(1, F_COMMIT, 30)
    with open(os.path.join(data_dir, "scanner_scan_005.cctf"), "wb") as fh:
        fh.write(s.buf)

    # scan_006: v3, savepoint/rollback/abort interplay then a bad-CRC boundary.
    #   TXN1, TXN2, SAVEPOINT sp1, TXN3, TXN4, ROLLBACK sp1 (drop 3,4), TXN5, COMMIT -> {1,2,5}
    #   TXN6, TXN7, ABORT (drop)
    #   TXN8, COMMIT -> {8}
    #   TXN9 (pending), bad-CRC frame -> boundary (drop 9)
    # recovered = {1,2,5,8}
    s = Stream()

    def v3_txn(seq, batt=90):
        tx_id = f"tx_scan_006_{seq:03d}"
        ts = start_ts + seq * 10
        temp = _temp_v3(5, seq)
        s.add(3, F_TXN, seq, txn_payload(3, tx_id, "scan_006", seq, ts, temp, batt))
        return tx_id, ts, temp

    committed_seqs = []
    t1 = v3_txn(1); t2 = v3_txn(2)
    s.add(3, F_SAVEPOINT, 0, sp_payload("sp1"))
    v3_txn(3); v3_txn(4)
    s.add(3, F_ROLLBACK, 0, sp_payload("sp1"))
    t5 = v3_txn(5)
    s.add(3, F_COMMIT, 5)
    committed_seqs += [1, 2, 5]
    v3_txn(6); v3_txn(7)
    s.add(3, F_ABORT, 0)
    t8 = v3_txn(8)
    s.add(3, F_COMMIT, 8)
    committed_seqs += [8]
    v3_txn(9)
    bad_frame, _, _ = s.frame_bytes(3, F_TXN, 99, txn_payload(3, "tx_scan_006_099", "scan_006", 99, start_ts + 990, _temp_v3(5, 99), 80))
    bad = bytearray(bad_frame)
    bad[-5] ^= 0xFF  # corrupt the CRC (within the crc field) -> boundary at this frame
    buf = s.buf + bytes(bad)
    with open(os.path.join(data_dir, "scanner_scan_006.cctf"), "wb") as fh:
        fh.write(buf)

    return tx_map, start_ts


def _build_metrics(data_dir, seed):
    warehouses = ["wh_north", "wh_south", "wh_east"]
    zones = ["zone_A", "zone_B", "zone_C"]
    scanners = ["scan_001", "scan_002", "scan_003", "scan_004", "scan_005"]
    s = Stream()
    count = 1500 + (seed % 5) * 30
    for i in range(count):
        wh = warehouses[i % len(warehouses)]
        zone = zones[(i // 3) % len(zones)]
        s_id = scanners[i % len(scanners)]
        metric_name = "temp_reading" if i % 2 == 0 else "humidity_reading"
        ts = 1717200000 + (i * 7)
        rec = {
            "metric_name": metric_name,
            "timestamp": ts,
            "value": round(-18.5 + (i % 15) * 0.1, 2) if metric_name == "temp_reading" else round(45.0 + (i % 20) * 0.5, 2),
            "attributes": {
                "warehouse_id": wh,
                "zone_id": zone,
                "scanner_id": s_id,
                "session_id": f"sess_{seed}_{i}",
                "request_id": f"req_{seed}_{i * 13}",
                "client_ip": f"10.0.1.{i % 254}",
            },
        }
        s.add(2, F_METRIC, i, metric_payload(rec))
    # truncated trailing frame (power cut) -> must be ignored, prior 'count' kept
    tail, _, _ = s.frame_bytes(2, F_METRIC, count, metric_payload({"metric_name": "temp_reading", "timestamp": 1, "value": 0.0, "attributes": {}}))
    buf = s.buf + tail[: len(tail) // 2]
    with open(os.path.join(data_dir, "metrics.cctf"), "wb") as fh:
        fh.write(buf)


def _build_dlq(data_dir, tx_map, start_ts, seed):
    dlq_dir = os.path.join(data_dir, "dlq")
    os.makedirs(dlq_dir, exist_ok=True)
    rng = random.Random(seed)

    dlq_records = []
    dup_txs = ["tx_scan_005_010", "tx_scan_005_020", "tx_scan_002_015"]
    for tx_id in dup_txs:
        orig = tx_map[tx_id]
        dlq_records.append({
            "transaction_id": tx_id, "scanner_id": orig["scanner_id"], "sequence": orig["sequence"],
            "timestamp": orig["timestamp"] + rng.choice([-30, -10, 10, 30]),
            "temperature_c": orig["temperature_c"], "battery_level": orig["battery_level"], "fw": "fw_2.3.1",
        })
    corr_txs = ["tx_scan_005_025", "tx_scan_002_020"]
    for tx_id in corr_txs:
        orig = tx_map[tx_id]
        dlq_records.append({
            "transaction_id": tx_id, "scanner_id": orig["scanner_id"], "sequence": orig["sequence"],
            "timestamp": orig["timestamp"] + 120,
            "temperature_c": round(orig["temperature_c"] - 1.5, 4), "battery_level": orig["battery_level"] - 1, "fw": "fw_2.3.1",
        })
    for i in range(1, 11):
        dlq_records.append({
            "transaction_id": f"tx_dlq_late_{i:03d}", "scanner_id": "scan_005", "sequence": 100 + i,
            "timestamp": 1717210000 + i * 10, "temperature_c": -19.1234, "battery_level": 85, "fw": "fw_2.3.1",
        })

    rng.shuffle(dlq_records)
    chunk_size = (len(dlq_records) + 2) // 3
    for idx in range(3):
        chunk = dlq_records[idx * chunk_size:(idx + 1) * chunk_size]
        s = Stream()
        for seq, rec in enumerate(chunk, start=1):
            s.add(2, F_TXN, seq, json.dumps(rec, separators=(",", ":")).encode("utf-8"))
        s.add(2, F_COMMIT, len(chunk))
        with open(os.path.join(dlq_dir, f"dlq_batch_{idx + 1}.cctf"), "wb") as fh:
            fh.write(s.buf)


def generate_all_data(data_dir, seed=42):
    os.makedirs(data_dir, exist_ok=True)
    tx_map, start_ts = _build_scanner_files(data_dir, seed)
    _build_metrics(data_dir, seed)
    _build_dlq(data_dir, tx_map, start_ts, seed)


# ---- golden reference artifacts (self-contained worked example) ----

def _decode_frames(raw):
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


def _recover(frames, schema_versions):
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


def _projection(record):
    obj = {}
    for k in HASH_FIELDS:
        if k == "temperature_c":
            obj[k] = round(record["temperature_c"], 2)
        else:
            obj[k] = record[k]
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _chain_root(sorted_records):
    state = hashlib.sha256(CHAIN_INIT).digest()
    for r in sorted_records:
        state = hashlib.sha256(state + _projection(r)).digest()
    return state


def emit_golden(golden_dir):
    os.makedirs(golden_dir, exist_ok=True)
    # Tiny v3 example exercising the deci-Celsius transform, a savepoint/rollback,
    # an uncommitted tail TXN, and a truncated trailing COMMIT.
    #   TXN1, TXN2, SAVEPOINT sp, TXN3, ROLLBACK sp (drop 3), TXN4, COMMIT -> {1,2,4}
    #   TXN5 (pending), truncated COMMIT -> boundary (drop 5)
    s = Stream()
    base = 1717200000

    def gtxn(seq, temp_c):
        s.add(3, F_TXN, seq, txn_payload(3, f"tx_g_{seq:03d}", "scan_g", seq, base + seq * 10, temp_c, 99 - seq))

    gtxn(1, -18.3)
    gtxn(2, -17.9)
    s.add(3, F_SAVEPOINT, 0, sp_payload("sp"))
    gtxn(3, -16.5)
    s.add(3, F_ROLLBACK, 0, sp_payload("sp"))
    gtxn(4, -15.2)
    s.add(3, F_COMMIT, 4)
    gtxn(5, -14.0)
    trailing, _, _ = s.frame_bytes(3, F_COMMIT, 5)
    buf = s.buf + trailing[:-3]
    with open(os.path.join(golden_dir, "sample_scanner.cctf"), "wb") as fh:
        fh.write(buf)

    frames = _decode_frames(buf)
    recovered = _recover(frames, SCHEMA_VERSIONS)
    with open(os.path.join(golden_dir, "sample_recovered.json"), "w") as fh:
        json.dump(recovered, fh, indent=2)

    canon_lines = [_projection(r).decode("utf-8") for r in recovered]
    with open(os.path.join(golden_dir, "sample_canonical.txt"), "w") as fh:
        fh.write("\n".join(canon_lines) + "\n")

    sorted_recs = sorted(recovered, key=lambda x: (x.get("scanner_id", ""), x.get("sequence", 0), x.get("timestamp", 0)))
    root = _chain_root(sorted_recs)
    n = len(sorted_recs)
    key = hashlib.sha256(SIG_PREFIX + str(n).encode("utf-8")).digest()
    sig = hmac.new(key, root, hashlib.sha256).digest()
    with open(os.path.join(golden_dir, "sample_root.hex"), "w") as fh:
        fh.write(root.hex() + "\n")
    with open(os.path.join(golden_dir, "sample_signature.hex"), "w") as fh:
        fh.write(sig.hex() + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default="data/raw")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--emit-golden", default=None)
    args = parser.parse_args()
    if args.emit_golden:
        emit_golden(args.emit_golden)
    else:
        generate_all_data(args.data_dir, args.seed)
