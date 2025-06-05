#!/bin/sh
set -e
set -x

# Chown the mounted data volume
chown -R service:service "/data/"

# Start cleanup task
python3 cleanup.py &

# Launch our service as user 'service'
exec gosu service ./syncryn1z3
