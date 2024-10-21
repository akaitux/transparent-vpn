#!/opt/bin/bash

#/opt/bin/check_vpn_dns.sh



DNSMASQ_CONF="/opt/etc/dnsmasq.conf"
DNSMASQ_INITD="/opt/etc/init.d/S56dnsmasq"
DNSMASQ_DNS="127.0.0.1:65053"
WG_DNS="10.224.0.1"

iptables_cmd="PREROUTING -t nat -p udp -m udp --dport 53 -j DNAT --to-destination $DNSMASQ_DNS"
iptables_add_cmd="iptables -I $iptables_cmd"
iptables_check_cmd="iptables -C $iptables_cmd"
iptables_del_cmd="iptables -D $iptables_cmd"


WG_IF=`ip -o -4 addr show | egrep "10\.224\.0\.[0-9]{1,3}\/" | awk '{print $2}'`
if [ -z "$WG_IF" ]; then
    echo "wg interface for 10.224.0.0/ not found";
    exit 0
fi

is_interface_up=`ip a show "$WG_IF" up | grep UP &>/dev/null ; echo $?`

if [ "$is_interface_up" -eq "0" ]; then
  if ! $iptables_check_cmd; then
    `$iptables_add_cmd`
  else
    echo "PREROUTING rule already exists"
  fi
#  if ! grep -q "server=$WG_DNS" $DNSMASQ_CONF; then
#      sed -ie "/^strict-order/a server=$WG_DNS" $DNSMASQ_CONF
#      $DNSMASQ_INITD restart
#  fi
fi


if [ "$is_interface_up" == "1" ]; then
    `$iptables_del_cmd` || true
#    if grep -q "server=$WG_DNS" $DNSMASQ_CONF; then
#	sed -ie "/^server=$WG_DNS/d" $DNSMASQ_CONF
#
fi
