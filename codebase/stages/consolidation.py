def consolidate_and_checksum(all_records: list, output_path: str, root_path: str, sig_path: str) -> str:
    """
    Canonicalizes and sorts all records, writing the consolidated ledger to output_path.
    Computes the order-dependent chained SHA-256 root (written to root_path) and the
    record-count-derived HMAC-SHA256 signature (written to sig_path).
    Returns the hex string of the chained root.
    """
    raise NotImplementedError("Stage 4: consolidate_and_checksum is not implemented yet.")
