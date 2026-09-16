# Cold-Chain Reconciliation Pipeline Specifications

Your pipeline ingests scanner transaction journals and telemetry that are persisted in the
**CCTF (Cold-Chain Telemetry Frame)** append-only binary wire format. It must recover them from
power-cut failure conditions, aggregate telemetry, integrate a delayed dead-letter queue (DLQ),
and emit a consolidated ledger with a chained cryptographic root and a derived-key signature.

A self-contained worked example lives under `docs/golden/`. Validate your decoder and checksum
math against it **before** running on the real data — it is the authoritative contract for any
detail you find ambiguous below.

## CCTF binary frame layout

A `.cctf` file is a concatenation of variable-length frames. There is no file header. All
multi-byte integers are **big-endian**.

```
offset 0        : magic   = 0x43 0x43  (the two ASCII bytes "CC")
offset 2        : version = uint8      (1, 2, or 3)
offset 3        : ftype   = uint8      (1=TXN, 2=METRIC, 3=COMMIT, 4=ABORT, 5=SAVEPOINT, 6=ROLLBACK)
offset 4        : seq     = uint32     (frame sequence number within the file)
offset 8        : plen    = uint16     (payload length in bytes)
offset 10       : payload = plen bytes (UTF-8 JSON object; see per-type rules below)
offset 10+plen  : crc     = uint32     (CRC-32, see below)
offset 14+plen  : chain   = uint32     (per-frame chain link, see below)
```

Total frame size is `18 + plen` bytes.

- **CRC-32** covers the first `10 + plen` bytes of the frame (header + payload, *not* including the
  crc or chain fields) and uses the standard IEEE 802.3 algorithm as implemented by Python's
  `zlib.crc32(...) & 0xFFFFFFFF`.
- **chain** is a running per-frame integrity link computed over the *previous* frame's chain value
  and *this* frame's crc:
  `chain_i = zlib.crc32(struct.pack(">I", chain_{i-1}) + struct.pack(">I", crc_i)) & 0xFFFFFFFF`,
  where the seed for the first frame in every file is `chain_{-1} = 0` (each file starts a fresh
  chain). The chain detects reordered, dropped, or spliced frames even when each frame's own CRC is
  intact.

Payload rules by frame type:
- **TXN / METRIC**: UTF-8 JSON object.
- **SAVEPOINT / ROLLBACK**: UTF-8 JSON object `{"savepoint": "<name>"}`.
- **COMMIT / ABORT**: empty payload (`plen == 0`).

### Frame decoding rules (corruption boundary)

Walk frames from offset 0, maintaining the running `chain` value (initialized to 0). **Stop decoding
the file at the first frame that is invalid**, treating all remaining bytes as untrusted tail garbage
from a crash. A frame is invalid when any of these holds:
- Fewer than 10 bytes remain to read the header.
- The magic bytes are not `"CC"`.
- Fewer than `10 + plen + 8` bytes remain (truncated payload, crc, or chain — a partial write).
- The stored CRC does not equal the recomputed CRC (mid-stream byte corruption).
- The stored chain link does not equal the recomputed chain link (reordering / splice corruption).

Frames decoded **before** the first invalid frame are trusted. Note that a frame whose own CRC is
valid is still rejected — and ends the file — if its chain link does not match; the frames after it,
including any otherwise-valid COMMIT, are *not* trusted.

## Stage 1: Ledger Recovery

- **Entrypoint**: `recover_ledgers(data_dir: str, output_dir: str) -> dict` in `stages/recovery.py`
  (the orchestrator additionally supplies the loaded config so schema migration has the field map).
- Inputs are files named `scanner_<id>.cctf` and, for atomic-rename gaps, `scanner_<id>.cctf.tmp`.
- **Transactional commit / rollback with savepoints**: a scanner streams TXN frames and periodically
  writes a COMMIT frame. Maintain a *pending* buffer and a *savepoints* table (`name -> pending
  length at the time the savepoint was taken`):
  - On a **TXN** frame, append the decoded record to *pending*.
  - On a **SAVEPOINT** frame, record `savepoints[name] = len(pending)` (re-establishing an existing
    name overwrites its marker).
  - On a **ROLLBACK** frame (rollback *to* the named savepoint): if `name` is known, truncate
    *pending* back to `savepoints[name]` (discard every record appended after the savepoint was
    taken), keep that savepoint, and discard any savepoints whose marker is greater than the target
    (they were taken after it). If `name` is unknown, the frame is a no-op.
  - On a **COMMIT** frame, move all *pending* records to *committed*, then clear *pending* and the
    savepoints table.
  - On an **ABORT** frame, discard *pending* and clear the savepoints table (without committing).
  - When the stream ends (including ending early because of the corruption boundary), any records
    still in *pending* are **uncommitted** and must be **dropped** — they did not survive the power
    cut.
- **Schema migration across scanner versions**: for a frame of version `V`, the temperature is stored
  under the key `config["schema_versions"][str(V)]["temperature_field"]`, and the stored value uses
  the unit named by that entry's `"scale"`:
  - `"scale": "celsius"` — the stored value is already degrees Celsius.
  - `"scale": "deci_celsius"` — the stored value is an **integer in tenths of a degree Celsius**;
    the canonical value is `stored / 10.0`.
  Every recovered record must expose the temperature under the canonical key `temperature_c` (a
  float in degrees Celsius). Rename the source field to `temperature_c` when it differs and apply the
  unit conversion; leave all other fields untouched. (Version 1 has no `fw` key; versions 2 and 3 do —
  this heterogeneity is expected.)
- **Rename gap**: if both `scanner_<id>.cctf` and `scanner_<id>.cctf.tmp` exist, recover committed
  records from **both** files and merge. When the same `transaction_id` appears more than once
  (across files), keep the record with the **higher** `timestamp`.
- **Outputs** (written under `output_dir`):
  - `recovered_<id>.json` — JSON list of the merged, deduplicated committed records for scanner `<id>`.
  - `audit_recovery.json` — JSON object mapping `{<scanner_id>: <recovered_record_count>}`.

## Stage 2: Telemetry Aggregation

- **Entrypoint**: `aggregate_metrics(metrics_file: str, config: dict) -> list` in `stages/aggregation.py`.
- `metrics_file` is a `.cctf` file of METRIC frames (decode with the same rules above, including the
  chain check; trailing truncated frames are dropped). Each payload is a JSON object
  `{"metric_name", "timestamp", "value", "attributes": {...}}`.
- Drop any record missing `metric_name`, `timestamp`, or `value`.
- Keep only attribute keys listed in `config["metric_config"]["whitelisted_attributes"]`.
- Bucket by hour: `bucket = timestamp - (timestamp % (aggregation_interval_hours * 3600))`.
- Group by `(metric_name, bucket, filtered_attributes)` and compute the `mean` of `value`,
  rounded to 4 decimals.
- Each output object is `{"metric_name", "timestamp": bucket, "value": mean, "attributes": filtered}`.
- Sort ascending by `metric_name`, then `timestamp`, then the `sort_keys` JSON serialization of
  `attributes`.
- The orchestrator writes the list to `aggregated_metrics.json` under `output_dir`.

## Stage 3: Dead-Letter Queue (DLQ) Replay

- **Entrypoint**: `replay_dead_letters(recovered_dir: str, dlq_dir: str, config: dict) -> tuple`
  in `stages/replay.py`.
- Load the base records from the `recovered_<id>.json` files in `recovered_dir`.
- Process the DLQ files `dlq_dir/dlq_*.cctf` in **sorted filename order**. Each DLQ file is itself a
  CCTF stream of TXN frames terminated by a COMMIT — recover its committed records with the same
  Stage 1 commit/rollback rules.
- For each DLQ record:
  - If its `transaction_id` is **not** already present, integrate it (add it).
  - If it **is** present, compute `drift = abs(dlq_timestamp - existing_timestamp)`.
    - `drift <= config["lock_timeout_sec"]` → discard the DLQ record as a duplicate.
    - `drift > config["lock_timeout_sec"]` → treat as a lineage correction: replace the existing
      record with the DLQ record (this counts as an integration).
- **Return** `(all_combined_unique_records, audit_dict)`.
- The orchestrator writes `audit_replay.json` =
  `{"integrated_dlq_records": <count>, "discarded_duplicates": <count>}`.

## Stage 4: Consolidation, Chained Root, and Signature

- **Entrypoint**:
  `consolidate_and_checksum(all_records: list, output_path: str, root_path: str, sig_path: str) -> str`
  in `stages/consolidation.py`.
- Sort all records ascending by `scanner_id` (string), then `sequence` (numeric), then `timestamp`.
- Write the sorted **full** records to `output_path` as JSON with `indent=2`.
- **Chained root** (order-dependent — a single wrong record, missing record, or wrong sort breaks
  every downstream byte):
  - The hash *projection* of a record is the minified, sorted-key JSON of **only** these fields:
    `transaction_id, scanner_id, sequence, timestamp, temperature_c`, where `temperature_c` is
    **rounded to 2 decimals**. All other fields (e.g. `battery_level`, `fw`) are excluded.
    Concretely: `json.dumps({...projected...}, separators=(",", ":"), sort_keys=True)`.
  - Initialize `state = SHA256(b"CCTF-ROOT-V1")`. For each record in sorted order,
    `state = SHA256(state_digest + projection_bytes)`. The final 32-byte `state` digest is the root.
  - Write the raw 32 bytes to `root_path` (`ledger_root.bin`).
- **Signature** (chains on both the root and the record count, so recovery errors propagate here):
  - Let `N` be the number of consolidated records. Derive
    `key = SHA256(b"coldchain-fleet|" + str(N).encode("utf-8"))`.
  - `signature = HMAC-SHA256(key, root_bytes)`. Write the raw 32 bytes to `sig_path`
    (`ledger_signature.bin`).
- Return the hex string of the root.

## Golden reference (`docs/golden/`)

- `sample_scanner.cctf` — a tiny version-3 stream exercising the deci-Celsius transform, a
  savepoint/rollback (one TXN rolled back), an uncommitted tail TXN, and a truncated trailing COMMIT.
- `sample_recovered.json` — the exact committed records your Stage 1 must produce for that sample.
- `sample_canonical.txt` — one line per record: the exact hash-projection string for that record.
- `sample_root.hex` / `sample_signature.hex` — the expected chained root and signature for the sample.

If your implementation reproduces every golden artifact byte-for-byte, your decoder, chain check,
savepoint state machine, version migration, projection, and checksum math are correct.
