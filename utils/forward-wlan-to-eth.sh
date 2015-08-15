#!/bin/sh
#
# Forward wlan interface to ethernet if.
# Copyright (C) 2015  LaBriqueInterNet <discussion@listes.labriqueinter.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

show_usage() {
cat <<EOF
# NAME

  $(basename "$0") -- Configure internet forwarding (from wlan to eth)

# OPTIONS

  -i    internet interface          (default: wlan0)
  -o    brique connected interface  (default: eth0)
  -a    action (start/stop)         (default: null)

EOF
exit 1
}

wlan='wlan0'
eth='eth0'
action=''

while getopts ":i:o:a" opt; do
  case $opt in
    i)
      wlan=$OPTARG
      ;;
    o)
      eth=$OPTARG
      ;;
    a)
      action=$OPTARG
      ;;
    \?)
      show_usage
      ;;
  esac
done

if [ "$action" = "start" ]; then
  # Configure internet forwarding from wlan interface to ethernet interface
  ip a a 172.16.42.1/24 dev "${eth}"
  echo 1 > /proc/sys/net/ipv4/ip_forward

  iptables -t nat -A POSTROUTING -o "${wlan}" -j MASQUERADE
  iptables -A FORWARD -i "${wlan}" -o "${eth}" -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A FORWARD -i "${eth}" -o "${wlan}" -j ACCEPT

  echo "install dnsmasq, and run: "
  echo "$ dnsmasq -d -i eth0 --dhcp-range=172.16.42.200,172.16.42.250,4h"

  echo "on the second laptop, just run: "
  echo "$ ip a a eth0 172.16.42.201/24;echo 'nameserver 80.67.188.188' > /etc/resolv.conf"

elif [ "$action" = "stop" ]; then
  # Remove configured forwarding from wlan interface
  iptables -F FORWARD
  iptables -t nat -F POSTROUTING

  echo 0 > /proc/sys/net/ipv4/ip_forward
  ip a d 172.16.42.1/24 dev "${eth}"

  echo "stop dnsmasq"
  echo "and maybe restart your firewall :-)"

else
  show_usage
fi
