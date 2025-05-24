from scapy.all import sniff, IP, ICMP
from utils.logger import log_attack
import time
from collections import defaultdict

class IcmpTunnelDetector:
    def __init__(self, iface="ens33", threshold=10, size_limit=200, window=10):
        self.iface = iface
        self.icmp_log = defaultdict(list)
        self.threshold = threshold
        self.size_limit = size_limit
        self.window = window

    def process_packet(self, packet):
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            icmp_layer = packet[ICMP]
            ip_layer = packet[IP]
            current_time = time.time()

            if icmp_layer.type == 8:
                src = ip_layer.src
                dst = ip_layer.dst
                size = len(icmp_layer.payload)

                self.icmp_log[src].append(current_time)

                self.icmp_log[src] = [
                    ts for ts in self.icmp_log[src]
                    if current_time - ts <= self.window
                ]

                if len(self.icmp_log[src]) > self.threshold or size > self.size_limit:
                    log_attack(f"Подозрение на ICMP туннель (size={size})", f"{src} -> {dst}")
                    self.icmp_log[src].clear()

    def run(self):
        print("[*] Мониторинг ICMP-туннелей активен...")
        sniff(iface=self.iface, filter="icmp", prn=self.process_packet, store=0)