from scapy.all import sniff, IP, ICMP
from collections import defaultdict
import time
from utils.logger import log_attack

class ICMPFloodDetector:
    def __init__(self, iface="ens33", threshold=100, time_window=10):
        self.iface = iface
        self.threshold = threshold
        self.time_window = time_window
        self.packet_log = defaultdict(list)

    def process_packet(self, packet):
        if packet.haslayer(IP) and packet.haslayer(ICMP):
            if packet[ICMP].type == 8:
                src_ip = packet[IP].src
                now = time.time()
                self.packet_log[src_ip].append(now)

                self.packet_log[src_ip] = [
                    ts for ts in self.packet_log[src_ip]
                    if now - ts <= self.time_window
                ]

                if len(self.packet_log[src_ip]) > self.threshold:
                    log_attack("ICMP Flood обнаружен", src_ip, "Зачем опять флудят???")
                    self.packet_log[src_ip].clear()

    def run(self):
        print("[*] Мониторинг ICMP флуда запущен...")
        sniff(iface=self.iface, prn=self.process_packet, store=0)