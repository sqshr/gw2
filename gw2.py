#!/usr/bin/python

import sys,os,argparse,string,netifaces,logging
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
import scapy.all as scapy

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

#Get MAC address for each IP
ipdict = {}
for ip in iplist:
    arp_request = scapy.ARP( pdst = ip )
    response = scapy.sr1( arp_request, timeout=0.2 )
    if response:
        mac = response.hwsrc
        ipdict[ip] = mac
    if not response:
        print("ERROR: No MAC address found for "+ip)

#Array of routing IPs:
routers=[]

def isrouter(response):
    if response.haslayer("ICMP") and synack_reply["ICMP"].type == 11 and synack_reply["ICMP"].code == 0:
        if router_ip not in routers:
            routers.append(router_ip)

for ip in ipdict:
    router_ip = ip
    mac = ipdict[ip]

    #Force packets to our potential router
    ether = scapy.Ether(src=source_mac, dst=mac)

    #Send SYN packet to port 80
    ip = scapy.IP( src=source_ip , dst=args.ip, ttl=1 )
    syn_packet = scapy.TCP(sport=1500, dport=80, flags="S" )
    synack_reply = scapy.srp1(ether/ip/syn_packet, timeout=0.2 )
    if synack_reply:
        #for p in synack_reply:
        #    a = p.show(dump=True)
        #    print(type(a))
        #    print(a)
        isrouter(synack_reply)

    #send ICMP ping
    packet = ether/scapy.IP(dst=args.ip, ttl=1)/scapy.ICMP()
    ping_reply = scapy.srp1(packet,timeout=0.2)
    if ping_reply:
        #for p in ping_reply:
        #    a = p.show(dump=True)
        #    #print(type(a))
        #    print(a)
        isrouter(ping_reply)

for ip in routers:
    print(ip)
