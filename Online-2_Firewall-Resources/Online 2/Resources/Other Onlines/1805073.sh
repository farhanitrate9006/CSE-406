# 1805073 (20.40.48.65)
#                                      eth0@if21
# attacker ----------- hostA --------( 10.9.0.11 )----router
# 10.9.0.1            10.9.0.5                          |
#                                                  192.168.60.11 (eth1@if23)
#                                                       |
# --------------------host1 -------- host2 -----------host3------
#                 (192.168.60.5)      (60.6)          (60.7)

#1. All the internal hosts run a telnet server. Outside hosts can access all internal Telnet servers
iptables -A FORWARD -i eth0 -p tcp --dport 23 -j ACCEPT

#2. Machine with IP address 192.168.60.7 can connect to 10.9.0.5 via TELNET
iptables -A FORWARD -i eth1 -s 192.168.60.7 -d 10.9.0.5 -p tcp --dport 23 -j ACCEPT

#3. No other machine can connect to any other machine via TELNET
iptables -A FORWARD -i eth1 -p tcp --dport 23 -j DROP

#4. Internal hosts can ping outside hosts
iptables -A FORWARD -i eth1 -p icmp --icmp-type echo-request -j ACCEPT

#5. External host with IP address 10.9.0.5 can ping to router and 192.168.60.5 
# (10.9.0.5 cannot ping to 192.168.60.6 and 192.168.60.7)
iptables -A FORWARD -i eth0 -s 10.9.0.5 -d 192.168.60.5 -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -s 10.9.0.5 -p icmp --icmp-type echo-request -j ACCEPT

#6. Internal hosts cannot ping each other ((apply to all internal hosts))
iptables -A OUTPUT -p icmp --icmp-type echo-request -j DROP

#7. No other machine on the external network can ping to the internal network
iptables -A FORWARD -i eth0 -p icmp --icmp-type echo-request -j DROP