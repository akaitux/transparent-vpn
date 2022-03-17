#!/bin/sh
WG_IF=`ip -o -4 addr show | egrep "10\.224\.0\.[0-9]{1,3}\/15" | awk '{print $2}'`
WG_DNS="10.224.0.1"

is_interface_up=`ip a show "$WG_IF" up | grep UP &>/dev/null ; echo $?`
is_dnat_exists=`iptables -t nat -L -n | grep "to:${WG_DNS}:53" >/dev/null ; echo -n $?`

if [ "$is_interface_up" == "0" ]; then
    if [ ! "$is_dnat_exists" = 0 ]; then
    	iptables -t nat -I PREROUTING -p udp -m udp --dport 53 -j DNAT --to-destination $WG_DNS:53
    fi
fi

if [ "$is_interface_up" == "1" ]; then
    iptables -t nat -D PREROUTING -p udp -m udp --dport 53 -j DNAT --to-destination $WG_DNS:53
fi
