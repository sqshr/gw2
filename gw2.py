#!/usr/bin/python

import sys,os,argparse,string,netifaces,scapy.all as scapy

parser = argparse.ArgumentParser(description='This tool tries to find gateways present on a local LAN')
parser.add_argument('-i', '--ip', default='8.8.8.8', help='The IP address to try and reach')
parser.add_argument('-I', '--interface', default='eth0', help='The network interface to use')
parser.add_argument('ips', help='File containing IP addresses to try to use as a gateway')
args = parser.parse_args()

#Makes scapy quiet
scapy.conf.verb = 0

#Gets source IP from selected interface
source_ip = netifaces.ifaddresses(args.interface)[netifaces.AF_INET][0]['addr']
source_mac = netifaces.ifaddresses(args.interface)[netifaces.AF_LINK][0]['addr']

#Creates a list from the MAC address file
iplist = open(args.ips).read().splitlines()

#TODO: needs to validate IP addresses

#Get MAC address for each IP
ipdict = {}
for ip in iplist:
    arp_request = scapy.ARP( pdst = ip )
    response = scapy.sr1( arp_request, timeout=1 )
    if response:
        mac = response.hwsrc
        ipdict[ip] = mac

#Array of routing IPs:
routers=[]

for ip in ipdict:
    router_ip = ip
    mac = ipdict[ip]

    #Force packets to our potential router
    ether = scapy.Ether(src=source_mac, dst=mac)

    #Send SYN packet to port 80
    ip = scapy.IP( src=source_ip , dst=args.ip, ttl=1 )
    syn_packet = scapy.TCP(sport=1500, dport=80, flags="S" )
    synack_reply = scapy.srp1(ether/ip/syn_packet, timeout=1 )
    print("SYN via "+router_ip)
    if synack_reply:
        #for p in synack_reply:
        #    a = p.show(dump=True)
        #    print(type(a))
        #    print(a)
        if synack_reply.haslayer("ICMP") and synack_reply["ICMP"].type == 11 and synack_reply["ICMP"].code == 0:
            if router_ip not in routers:
                routers.append(router_ip)

    #send ICMP ping
    packet = ether/scapy.IP(dst=args.ip, ttl=1)/scapy.ICMP()
    ping_reply = scapy.srp1(packet,timeout=1)
    if ping_reply:
        #for p in ping_reply:
        #    a = p.show(dump=True)
        #    #print(type(a))
        #    print(a)
        if ping_reply.haslayer("ICMP") and ping_reply["ICMP"].type == 11 and ping_reply["ICMP"].code == 0:
            if router_ip not in routers:
                routers.append(router_ip)

for ip in routers:
    print(ip)
