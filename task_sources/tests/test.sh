#!/bin/bash
set -euo pipefail

# python3 / python3-pip / python3-pytest are baked into the image at build time;
# no runtime install needed (sandbox has no internet).

# ── Service bootstrap (if needed) ──────────────────────────────────────
# Start any services the task requires.
# Database tasks: start the DB server and wait for readiness.

if command -v pg_isready &>/dev/null && [ -d /var/lib/postgresql ]; then
    su - postgres -c "pg_ctlcluster $(pg_lsclusters -h | awk '{print $1, $2}') start" 2>/dev/null || true
    for i in $(seq 1 30); do su - postgres -c "pg_isready" &>/dev/null && break; sleep 1; done
fi

if command -v mysqld_safe &>/dev/null && [ -d /var/lib/mysql ]; then
    mysqld_safe --skip-networking=0 &
    for i in $(seq 1 30); do mysqladmin ping --silent 2>/dev/null && break; sleep 1; done
fi

if command -v redis-server &>/dev/null && [ -f /etc/redis/redis.conf ]; then
    redis-server /etc/redis/redis.conf --daemonize no 2>/dev/null &
    for i in $(seq 1 30); do redis-cli ping 2>/dev/null | grep -q PONG && break; sleep 1; done
fi

if command -v mongod &>/dev/null && [ -d /var/lib/mongodb ]; then
    mongod --config /etc/mongod.conf 2>/dev/null &
    for i in $(seq 1 30); do mongosh --quiet --eval "db.runCommand({ping:1})" &>/dev/null && break; sleep 1; done
fi

# ── Run pytest with CTRF output ────────────────────────────────────────
mkdir -p /app
cd /app

# pytest is provided by the Dockerfile (python3-pytest); no runtime install.

# Copy test file from /tests into workspace
mkdir -p /app
cp /tests/test_outputs.py /app/test_outputs.py 2>/dev/null || true

# Run tests (disable errexit to capture exit code and write reward file).
# Avoid fail-fast so Harbor sees the full failing surface for partial scoring.
set +e
python3 -m pytest /app/test_outputs.py --no-header -p no:cacheprovider -vs 2>&1
test_status=$?
set -e

# Ensure logs directories exist (Harbor mounts /logs but may not create subdirs).
# Write reward to BOTH locations: nexus sandbox reads /logs/tests, Modal verifier reads /logs/verifier.
mkdir -p /logs/verifier /logs/tests

if [ $test_status -eq 0 ]; then
    echo 1 > /logs/verifier/reward.txt
    echo 1 > /logs/tests/reward.txt
else
    echo 0 > /logs/verifier/reward.txt
    echo 0 > /logs/tests/reward.txt
fi

exit "$test_status"
