#!/bin/bash
set -e

# Resolve the directory this script lives in so we can copy the reference
# implementation modules that ship alongside it (solution/stages/*.py and
# solution/recon_pipeline.py) into the workspace, rather than emitting them
# via inline heredocs.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p /workspace/coldchain-recon/stages

# Stage 0: shared CCTF frame decoder + transactional recovery
# Stage 1: Recovery
# Stage 2: Aggregation
# Stage 3: Replay
# Stage 4: Consolidation
cp "$SCRIPT_DIR/stages/cctf.py" /workspace/coldchain-recon/stages/cctf.py
cp "$SCRIPT_DIR/stages/recovery.py" /workspace/coldchain-recon/stages/recovery.py
cp "$SCRIPT_DIR/stages/aggregation.py" /workspace/coldchain-recon/stages/aggregation.py
cp "$SCRIPT_DIR/stages/replay.py" /workspace/coldchain-recon/stages/replay.py
cp "$SCRIPT_DIR/stages/consolidation.py" /workspace/coldchain-recon/stages/consolidation.py

# Orchestrator
cp "$SCRIPT_DIR/recon_pipeline.py" /workspace/coldchain-recon/recon_pipeline.py

python3 /workspace/coldchain-recon/recon_pipeline.py
