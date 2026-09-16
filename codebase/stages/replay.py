def replay_dead_letters(recovered_dir: str, dlq_dir: str, config: dict) -> tuple:
    """
    Reconciles dead-letter log records with recovered records.
    Filters out duplicates within lock timeout, returns consolidated list and audit info.
    """
    raise NotImplementedError("Stage 3: replay_dead_letters is not implemented yet.")
