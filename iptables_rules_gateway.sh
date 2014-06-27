#!/bin/sh

iptables -t nat -A PREROUTING -d 203.0.113.254 -p tcp --dport 8081 -j DNAT --to-destination 10.2.3.166:3128
iptables -t nat -A POSTROUTING -d 10.2.3.166 -p tcp -m tcp --dport 3128 -j SNAT --to-source 10.2.3.1

