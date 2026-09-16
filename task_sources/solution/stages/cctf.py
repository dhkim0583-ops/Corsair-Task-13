import struct
import zlib
import json

MAGIC = b"CC"
F_TXN = 1
F_METRIC = 2
F_COMMIT = 3
F_ABORT = 4
F_SAVEPOINT = 5
F_ROLLBACK = 6

def decode_frames(raw: bytes):
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

def migrate_record(rec, version, schema_versions):
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
            migrate_record(rec, version, schema_versions)
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
