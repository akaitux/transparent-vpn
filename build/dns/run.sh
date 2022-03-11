#!/usr/bin/with-contenv bash

if [[ ! -d "/storage/confdb" ]]; then
    knotc conf-init
fi

if [[ ! -f "/knot_aliases/aliases.conf" ]]; then
    cp /knot_aliases_default.conf /knot_aliases/aliases.conf
fi
# Remove knot runtime
rm -rf /rundir/*


cron
cd /dnsmap && nohup ./proxy.py -a 127.0.0.4 --iprange 10.224.0.0/15 2>&1 >/dev/null &
cd /
kresd -c /config/kresd.conf -n /knot_runtime
