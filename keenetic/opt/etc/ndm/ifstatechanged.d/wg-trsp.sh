#!/bin/sh

WG_IF=`ip -o -4 addr show | egrep "10\.224\.0\.[0-9]{1,3}\/15" | awk '{print $2}'`
WG_DNS="10.224.0.1"

if [ ! "$system_name" == "$WG_IF" ]; then
   exit 0
fi

if_dnat_exists=`iptables -t nat -L -n | grep "to:${WG_DNS}:53" >/dev/null ; echo -n $?`

if [ "$link" == "up" ] && [ "$connected" == "yes" ]; then
    if [ ! "$if_dnat_exists" = 0 ]; then
    	iptables -t nat -I PREROUTING -p udp -m udp --dport 53 -j DNAT --to-destination $WG_DNS:53
    fi
fi

if [ "$connected" == "no" ]; then
    iptables -t nat -D PREROUTING -p udp -m udp --dport 53 -j DNAT --to-destination $WG_DNS:53
fi

