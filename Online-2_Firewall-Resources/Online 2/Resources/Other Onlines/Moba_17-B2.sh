# 1805090 (20.40.48.65)
#                                      eth0@if21
# attacker ----------- hostA --------( 10.9.0.11 )----router
# 10.9.0.1            10.9.0.5                          |
#                                                  192.168.60.11 (eth1@if23)
#                                                       |
# --------------------host1 -------- host2 -----------host3------
#                 (192.168.60.5)      (60.6)          (60.7)

# 1. External Hosts cannot connect via SSH to the internal host.
# 2. No Host can connect via SSH to the router.
# 3. Internal Hosts can connect via SSH with each other.
# 4. Machine with IP address 10.9.0.5 can connect to 192.168.60.6 via TELNET
# 5. No other machine can connect to any other machine via TELNET.
# 6. Machine with IP address 10.9.0.1 can’t ping any other machine
# 7. Machine with IP address 10.9.0.5 can ping all other machines (except 10.9.0.1)
# 8. No other machine can ping any other machine.

# 1. External Hosts cannot connect via SSH to the internal host.
    iptables -A FORWARD -i eth0 -p tcp --dport 22 -j DROP
# 2. No Host can connect via SSH to the router.
    iptables -A INPUT -p tcp --dport 22 -j DROP
# 3. Internal Hosts can connect via SSH with each other. (no need)
    iptables -A FORWARD -i eth1 -p tcp --dport 22 -j ACCEPT
    iptables -A FORWARD -o eth1 -p tcp --sport 22 -j ACCEPT
# 4. Machine with IP address 10.9.0.5 can connect to 192.168.60.6 via TELNET
    iptables -A FORWARD -i eth0 -s 10.9.0.5 -d 192.168.60.6 -p tcp --dport 23 -j ACCEPT
    # QUESTION: should it be in two lines? like this:
    # iptables -A FORWARD -i eth0 -s 10.9.0.5     -p tcp --dport 23 -j ACCEPT
    # iptables -A FORWARD -o eth1 -d 192.168.60.6 -p tcp --dport 23 -j ACCEPT
# 5. No other machine can connect to any other machine via TELNET.
    iptables -A FORWARD -i eth0 -p tcp --dport 23 -j DROP
    iptables -A FORWARD -i eth1 -p tcp --dport 23 -j DROP
    # we are to add rule in hostA and VM as well
    iptables -A INPUT -p tcp --dport 23 -j DROP
# 6. Machine with IP address 10.9.0.1 can’t ping any other machine
    # for this we are to add rule in VM
    iptables -A OUTPUT -p icmp --icmp-type echo-request -j DROP
# 7. Machine with IP address 10.9.0.5 can ping all other machines (except 10.9.0.1)
    # for this we are to add rule in hostA
    iptables -A OUTPUT -s 10.9.0.1 -p icmp --icmp-type echo-request -j DROP
    iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
# 8. No other machine can ping any other machine.
    # for this we are to add rule in host1, host2, host3
    iptables -A OUTPUT -p icmp --icmp-type echo-request -j DROP