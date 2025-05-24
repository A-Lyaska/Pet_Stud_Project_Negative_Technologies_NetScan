from scapy.all import sniff, IP, ICMP, Raw
from utils.logger import log_attack
from collections import defaultdict
import time

class IcmpTunnelDetector:
    def __init__(self, iface="ens33", threshold=10, size_limit=100, window=10):
        self.iface = iface
        self.threshold = threshold
        self.size_limit = size_limit
        self.window = window
        self.icmp_log = defaultdict(list)

    def process_packet(self, packet):
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            src = packet[IP].src
            dst = packet[IP].dst
            current_time = time.time()

            self.icmp_log[src].append(current_time)
            self.icmp_log[src] = [
                t for t in self.icmp_log[src] if current_time - t <= self.window
            ]

            payload_size = 0
            if packet.haslayer(Raw):
                payload_size = len(packet[Raw].load)

            if len(self.icmp_log[src]) > self.threshold or payload_size > self.size_limit:
                log_attack(f"Подозрение на ICMP туннель {src} -> {dst} (count={len(self.icmp_log[src])}, size={payload_size})", src)
                self.icmp_log[src].clear()

    def run(self):
        print("[*] Мониторинг ICMP-туннелей активен...")
        sniff(iface=self.iface, filter="icmp", prn=self.process_packet, store=0)
