#!/opt/bin/bash

#VPN_DNS_SOCK="127.0.0.1:65053"
VPN_DNS_SOCK="10.224.0.1:53"
CHECK_DNS_IP="10.224.0.1"
TIME_WAIT_SECS=15

iptables_cmd="PREROUTING -t nat -p udp -m udp --dport 53 -j DNAT --to-destination $VPN_DNS_SOCK"
iptables_add_cmd="iptables -I $iptables_cmd"
iptables_check_cmd="iptables -C $iptables_cmd"
iptables_del_cmd="iptables -D $iptables_cmd"

counter=0
while ! ping -c1 -W 1 ${CHECK_DNS_IP} &>/dev/null; do
  counter=$((counter + 1))
  echo "vpn gw $CHECK_DNS_IP not available, try ${counter} of ${TIME_WAIT_SECS}"
  if [ "$counter" -ge "$TIME_WAIT_SECS" ]; then
    `$iptables_del_cmd` || true
    exit 1
  fi
done

if ! $iptables_check_cmd; then
  echo "Add iptables cmd: $iptables_add_cmd"
  `$iptables_add_cmd`
fi
