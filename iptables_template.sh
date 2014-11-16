#!/bin/bash

#############################################################
#															#
#	Iptables template for servers with one network adpater	#
#															#
#	Created by Konstantin Rudenkov <rudenkovk@gmail.com>	#
#															#
#															#
#############################################################


IPT="/sbin/iptables"

# Interface name (external)
EXT_IF="eth0"

# BlackList file
BLACKLIST_FILE="blacklist.txt"

# WhiteList file
WHITELIST_FILE="whitelist.txt"

# Clean all rules
${IPT} -F
${IPT} -X
${IPT} -t nat -F
${IPT} -t nat -X
${IPT} -t mangle -F
${IPT} -t mangle -X

# Default policy
${IPT} -P INPUT DROP
${IPT} -P OUTPUT ACCEPT
${IPT} -P FORWARD DROP

# Allow traffic on local interface
${IPT} -A INPUT -i lo -j ACCEPT

# Keep established connections
${IPT} -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Drop INVALID state traffic
${IPT} -A INPUT -m conntrack --ctstate INVALID -j DROP

# Default UDP rules
${IPT} -N udp_rules
#---------------------------------------------#
#
# Default TCP rules
${IPT} -N tcp_rules
${IPT} -A tcp_rules -p tcp --dport 80 -j ACCEPT 		# allow http
${IPT} -A tcp_rules -p tcp --dport 443 -j ACCEPT		# allow https
${IPT} -A tcp_rules -p tcp --dport 22 -j ACCEPT			# allow ssh
#---------------------------------------------#

# ICMP rules 
${IPT} -N icmp_rules
${IPT} -A icmp_rules -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j LOG --log-prefix 'PING : '
${IPT} -A icmp_rules -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT # allow ping
#---------------------------------------------#

# Drop packets with address from internal address pools
${IPT} -N internal_address_pool
${IPT} -A internal_address_pool -i ${EXT_IF} -s 10.0.0.0/8 -j LOG --log-prefix 'INTERNAL_ADDR'
${IPT} -A internal_address_pool -i ${EXT_IF} -s 10.0.0.0/8 -j DROP
${IPT} -A internal_address_pool -i ${EXT_IF} -s 172.16.0.0/12 -j LOG --log-prefix 'INTERNAL_ADDR'
${IPT} -A internal_address_pool -i ${EXT_IF} -s 172.16.0.0/12 -j DROP
${IPT} -A internal_address_pool -i ${EXT_IF} -s 192.168.0.0/16 -j LOG --log-prefix 'INTERNAL_ADDR'
${IPT} -A internal_address_pool -i ${EXT_IF} -s 192.168.0.0/16 -j DROP
${IPT} -A internal_address_pool -i ${EXT_IF} -s 224.0.0.0/4 -j LOG --log-prefix 'INTERNAL_ADDR'
${IPT} -A internal_address_pool -i ${EXT_IF} -s 224.0.0.0/4 -j DROP
${IPT} -A internal_address_pool -i ${EXT_IF} -s 240.0.0.0/5 -j LOG --log-prefix 'INTERNAL_ADDR'
${IPT} -A internal_address_pool -i ${EXT_IF} -s 240.0.0.0/5 -j DROP
${IPT} -A internal_address_pool -i ${EXT_IF} -s 127.0.0.0/8 -j LOG --log-prefix 'INTERNAL_ADDR'
${IPT} -A internal_address_pool -i ${EXT_IF} -s 127.0.0.0/8 -j DROP
#---------------------------------------------#

# Blacklist chain
${IPT} -N blacklist_rules
if [ -f ${BLACKLIST_FILE} ]; then
	BLACKLIST=$(cat ${BLACKLIST_FILE} | xargs)
	for addr in ${BLACKLIST}; do
		${IPT} -A blacklist_rules -i ${EXT_IF} -s ${addr} -j LOG --log-prefix 'BLACKLIST : '
		${IPT} -A blacklist_rules -i ${EXT_IF} -s ${addr} -j DROP
	done
fi

# Whitelist chain
${IPT} -N whitelist_rules
if [ -f ${WHITELIST_FILE} ]; then
	WHITELIST=$(cat ${WHITELIST_FILE} | xargs)
	for addr in ${WHITELIST}; do
		${IPT} -A blacklist_rules -i ${EXT_IF} -s ${addr} -j ACCEPT
	done
fi

#########################
#	Applying chains		#
#########################

${IPT} -A INPUT -j blacklist_rules
${IPT} -A INPUT -j whitelist_rules

${IPT} -A INPUT -j internal_address_pool
${IPT} -A INPUT -j icmp_rules

${IPT} -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j tcp_rules
${IPT} -A INPUT -p udp -m conntrack --ctstate NEW -j udp_rules

# Reject rules
${IPT} -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
${IPT} -A INPUT -p tcp -j REJECT --reject-with tcp-rst
${IPT} -A INPUT -j REJECT --reject-with icmp-proto-unreachable



# TODO: scans protection
# TODO: logging
