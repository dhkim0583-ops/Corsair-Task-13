"""Auto-generated validation tests for terminal-bench task.

Task: coldchain-reconciliation-pipeline
Category: data-processing/binary-wire-protocol-transactional-recovery
"""

import subprocess


def _run(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)


def test_check_1():
    """Stage 1: CCTF decode, CRC/truncation boundary, commit/rollback, schema migration, rename-gap merge"""
    result = _run('python3 /tests/verify.py --stage 1')
    output = result.stdout + result.stderr
    assert 'STAGE 1 OK' in output, (
        f"Expected substring not found for: Stage 1 recovery\n"
        f"Expected: 'STAGE 1 OK'\nOutput: {output[:600]}"
    )


def test_check_2():
    """Stage 2: metric-frame decode, whitelist filter, hourly aggregation"""
    result = _run('python3 /tests/verify.py --stage 2')
    output = result.stdout + result.stderr
    assert 'STAGE 2 OK' in output, (
        f"Expected substring not found for: Stage 2 aggregation\n"
        f"Expected: 'STAGE 2 OK'\nOutput: {output[:600]}"
    )


def test_check_3():
    """Stage 3: DLQ replay duplicate vs lineage-correction within/beyond lock timeout"""
    result = _run('python3 /tests/verify.py --stage 3')
    output = result.stdout + result.stderr
    assert 'STAGE 3 OK' in output, (
        f"Expected substring not found for: Stage 3 DLQ replay\n"
        f"Expected: 'STAGE 3 OK'\nOutput: {output[:600]}"
    )


def test_check_4():
    """Stage 4: canonical sort, chained SHA-256 root, and count-derived HMAC signature"""
    result = _run('python3 /tests/verify.py --stage 4')
    output = result.stdout + result.stderr
    assert 'STAGE 4 AND CHECKSUM OK' in output, (
        f"Expected substring not found for: Stage 4 consolidation/checksum\n"
        f"Expected: 'STAGE 4 AND CHECKSUM OK'\nOutput: {output[:600]}"
    )


def test_check_5():
    """Resilience: re-run the pipeline against freshly generated, randomized inputs"""
    result = _run('python3 /tests/verify.py --mutated')
    output = result.stdout + result.stderr
    assert 'MUTATED RUN OK' in output, (
        f"Expected substring not found for: mutated-data run\n"
        f"Expected: 'MUTATED RUN OK'\nOutput: {output[:600]}"
    )


def test_check_6():
    """Anti-shortcut: no hardcoded digests/constants inside the implemented modules"""
    result = _run('python3 /tests/verify.py --anti-shortcut')
    output = result.stdout + result.stderr
    assert 'ANTI-SHORTCUT OK' in output, (
        f"Expected substring not found for: anti-shortcut\n"
        f"Expected: 'ANTI-SHORTCUT OK'\nOutput: {output[:600]}"
    )


def test_check_7():
    """Orchestrator runs all four stages end to end and exits 0"""
    result = _run('python3 /workspace/coldchain-recon/recon_pipeline.py')
    assert result.returncode == 0, (
        f"Command failed (exit {result.returncode}): orchestrator end-to-end run\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_check_8():
    """Idempotence: a second successive run still reproduces the sealed ledger and signature"""
    result = _run('python3 /workspace/coldchain-recon/recon_pipeline.py && python3 /tests/verify.py --stage 4')
    output = result.stdout + result.stderr
    assert 'STAGE 4 AND CHECKSUM OK' in output, (
        f"Expected substring not found for: idempotence rerun\n"
        f"Expected: 'STAGE 4 AND CHECKSUM OK'\nOutput: {output[:600]}"
    )
