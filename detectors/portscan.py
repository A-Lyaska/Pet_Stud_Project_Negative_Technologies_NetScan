from scapy.all import sniff, IP, TCP
from utils.logger import log_attack
from collections import defaultdict
import time

class PortScanDetector:
    def __init__(self, iface="any", threshold=10, time_window=5):
        self.iface = iface
        self.threshold = threshold
        self.time_window = time_window
        self.connection_log = defaultdict(list)

    def process_packet(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags

            # Только SYN-пакеты
            if flags == "S":
                current_time = time.time()
                self.connection_log[src_ip].append((dst_port, current_time))

                # Оставляем только актуальные записи
                self.connection_log[src_ip] = [
                    (port, ts) for port, ts in self.connection_log[src_ip]
                    if current_time - ts <= self.time_window
                ]

                if len(set(port for port, _ in self.connection_log[src_ip])) > self.threshold:
                    log_attack("Port Scan Detected", src_ip)
                    self.connection_log[src_ip].clear()  # избежать дублирования

    def run(self):
        sniff(iface=self.iface, prn=self.process_packet, store=0)
