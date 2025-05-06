#!/bin/sh
set -e
set -x

# Launch our service as user 'service'
exec ptp4l -m -f ptp4l.conf -i eth0 -S -s
