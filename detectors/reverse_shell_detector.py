from scapy.all import sniff, IP, TCP
from utils.logger import log_attack

SUSPICIOUS_PORTS = [1337, 4321, 4444, 9001, 12345]
WHITELIST_PORTS = [80, 443, 53, 22]

class ReverseShellDetector:
    def __init__(self, iface="ens33"):
        self.iface = iface

    def process_packet(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            dst_ip = ip_layer.dst
            dst_port = tcp_layer.dport
            flags = tcp_layer.flags

            if flags == "S":
                if dst_port in SUSPICIOUS_PORTS or dst_port not in WHITELIST_PORTS:
                    log_attack(f"Предположительная попытка Reverse Shell на порту {dst_port}", dst_ip)

    def run(self):
        print("[*] Мониторинг Reverse Shell активен...")
        sniff(iface=self.iface, filter="tcp", prn=self.process_packet, store=0)