from scapy.all import sniff, IP, ICMP
from utils.logger import log_attack

class IcmpTunnelDetector:
    def __init__(self, iface="ens33", size_threshold=200):
        self.iface = iface
        self.size_threshold = size_threshold

    def process_packet(self, packet):
        if packet.haslayer(IP) and packet.haslayer(ICMP):
            ip_layer = packet[IP]
            icmp_layer = packet[ICMP]

            if icmp_layer.type == 8:
                payload_size = len(icmp_layer.payload)

                if payload_size > self.size_threshold:
                    log_attack(
                        f"Подозрение на ICMP-туннель (большой объём пакетов): {payload_size} байт",
                        ip_layer.src
                    )

    def run(self):
        print("[*] Мониторинг ICMP-туннелей активен...")
        sniff(iface=self.iface, filter="icmp", prn=self.process_packet, store=0)
