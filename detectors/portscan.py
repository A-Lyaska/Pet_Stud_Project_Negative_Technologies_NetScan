from scapy.all import sniff, IP, TCP
from utils.logger import log_attack
from collections import defaultdict
import time

class PortScanDetector:
    def __init__(self, iface="ens33", threshold=10, time_window=5):
        self.iface = iface
        self.threshold = threshold
        self.time_window = time_window
        self.connection_log = defaultdict(list)

    def process_packet(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            current_time = time.time()

            scan_type = None

            if flags == "S":
                scan_type = "SYN Port Scan"
            elif flags == 0:
                scan_type = "NULL Port Scan"
            elif flags == "F":
                scan_type = "FIN Port Scan"
            elif set(str(flags)) >= set("FPU"):
                scan_type = "XMAS Port Scan"

            if scan_type:
                self.connection_log[src_ip].append((dst_port, current_time, scan_type))

                # Очищаем старые записи
                self.connection_log[src_ip] = [
                    (port, ts, stype) for port, ts, stype in self.connection_log[src_ip]
                    if current_time - ts <= self.time_window
                ]

                # Считаем количество разных портов
                unique_ports = set(port for port, _, _ in self.connection_log[src_ip])

                if len(unique_ports) > self.threshold:
                    log_attack(scan_type, src_ip, "Опять индусы сканируют. Пора наложить санкции, мистер Президент")
                    self.connection_log[src_ip].clear()

    def run(self):
        print("[*] Мониторинг сканирования Открытых портов запущен...")
        sniff(iface=self.iface, prn=self.process_packet, store=0)
