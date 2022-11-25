#!/bin/sh


DNSMASQ_CONF="/opt/etc/dnsmasq.conf"
DNSMASQ_INITD="/opt/etc/init.d/S56dnsmasq"
DNSMASQ_DNS="127.0.0.1:65053"
WG_DNS="10.224.0.1"


WG_IF=`ip -o -4 addr show | egrep "10\.224\.0\.[0-9]{1,3}\/15" | awk '{print $2}'`
if [ -z "$WG_IF" ]; then
    echo "wg interface for 10.224.0.0/15 not found";
    exit 0
fi
if [ ! "$system_name" == "$WG_IF" ]; then
   exit 0
fi

if_dnat_exists=`iptables -t nat -L -n | grep "to:${WG_DNS}:53" >/dev/null ; echo -n $?`

if [ "$link" == "up" ] && [ "$connected" == "yes" ]; then
    if [ ! "$if_dnat_exists" = 0 ]; then
    	iptables -t nat -I PREROUTING -p udp -m udp --dport 53 -j DNAT --to-destination $DNSMASQ_DNS
    fi
    if ! grep -q "server=$WG_DNS" $DNSMASQ_CONF; then
	sed -ie "/^strict-order/a server=$WG_DNS" $DNSMASQ_CONF
	$DNSMASQ_INITD restart
    fi
fi

if [ "$connected" == "no" ]; then
    if grep -q "server=$WG_DNS" $DNSMASQ_CONF; then
	sed -ie "/^server=$WG_DNS/d" $DNSMASQ_CONF
	$DNSMASQ_INITD restart
    fi
fi
