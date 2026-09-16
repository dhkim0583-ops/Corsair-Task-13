import json
import os
from stages.cctf import decode_frames, F_METRIC

def aggregate_metrics(metrics_file: str, config: dict) -> list:
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
        aggregated.append({
            "metric_name": name,
            "timestamp": bucket,
            "value": round(sum(vals) / len(vals), 4),
            "attributes": dict(attrs_fs),
        })
    aggregated.sort(key=lambda x: (x["metric_name"], x["timestamp"], json.dumps(x["attributes"], sort_keys=True)))
    return aggregated
