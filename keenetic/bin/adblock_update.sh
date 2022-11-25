#!/bin/sh

curl --compressed https://cdn.raletag.gq/rueasyhosts.txt https://adaway.org/hosts.txt \
    | awk '{sub("\r$", ""); sub("^www\\.", "", $2); if ($0 && $0 !~ /^#/ && $2 && $2 !~ /^$/ && $2 != "localhost") print "server=/." $2 "/";}' \
    | sort -u > /opt/etc/adblock.dnsmasq

/opt/etc/init.d/S56dnsmasq restart
