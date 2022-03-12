#!/bin/bash
set -e

cp result/knot-aliases-alt.conf /etc/knot-resolver/aliases/aliases.conf
/command/s6-svc -r /run/service/knot-resolver

iptables -F azvpnwhitelist
while read -r line
do
    iptables -w -A azvpnwhitelist -d "$line" -j ACCEPT
done < result/blocked-ranges.txt

exit 0
