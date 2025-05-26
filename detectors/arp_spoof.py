from scapy.all import sniff, ARP
from utils.logger import log_attack
from collections import defaultdict
import threading

class ARPSpoofDetector:
    def __init__(self, iface="ens33"):
        self.iface = iface
        self.arp_table = defaultdict(set)

    def process_packet(self, packet):
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc

            self.arp_table[src_ip].add(src_mac)

            if len(self.arp_table[src_ip]) > 1:
                log_attack("ARP Spoofing Detected", src_ip)
                self.arp_table[src_ip].clear()

    def run(self):
        print("[*] Мониторинг ARP Spoofing активен...")
        sniff(iface=self.iface, filter="arp", prn=self.process_packet, store=0)