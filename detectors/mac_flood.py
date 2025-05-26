from scapy.all import sniff, Ether
from utils.logger import log_attack
from collections import defaultdict
import time

class MACFloodDetector:
    def __init__(self, iface="ens33", threshold=50, time_window=10):
        self.iface = iface
        self.threshold = threshold
        self.time_window = time_window
        self.mac_activity = defaultdict(list)

    def process_packet(self, packet):
        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
            now = time.time()

            self.mac_activity[src_mac].append(now)

            for mac in list(self.mac_activity):
                self.mac_activity[mac] = [t for t in self.mac_activity[mac] if now - t <= self.time_window]
                if not self.mac_activity[mac]:
                    del self.mac_activity[mac]

            if len(self.mac_activity) > self.threshold:
                log_attack("MAC Flooding / DHCP Starvation Detected", f"{len(self.mac_activity)} MACs", "Как же они достали с истощением DHCP и флудом Мак адресов")
                self.mac_activity.clear()

    def run(self):
        print("[*] Мониторинг MAC Flooding / DHCP Starvation активен...")
        sniff(iface=self.iface, prn=self.process_packet, store=0)
