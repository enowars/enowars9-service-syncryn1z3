#!/bin/sh
set -e
set -x

# Chown the mounted data volume
chown -R service:service "/data/"

# Launch our service as user 'service'
exec gosu service ./ptp-master -a $(hostname -I) -i ${INSTANCE_ID}
#exec gdbserver :1234 ./ptp-master -a $(hostname -I) -i ${INSTANCE_ID}
