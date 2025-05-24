from threading import Thread
from detectors.icmp_flood import ICMPFloodDetector
from detectors.icmp_tunnel import IcmpTunnelDetector
from detectors.portscan import PortScanDetector
from detectors.reverse_shell_detector import ReverseShellDetector
from detectors.ssh_bruteforce import SSHBruteForceDetector
from detectors.arp_spoof import ARPSpoofDetector
from detectors.mac_flood import MACFloodDetector

def main():
    print("[*] NT_NetScan запущен...")

    portscan_detector = PortScanDetector()
    ssh_bruteforce_detector = SSHBruteForceDetector()
    icmp_flood = ICMPFloodDetector()
    arp_spoof = ARPSpoofDetector()
    mac_flood = MACFloodDetector()
    revers_shell = ReverseShellDetector()
    icmp_tunnel = IcmpTunnelDetector()

    t1 = Thread(target=portscan_detector.run)
    t2 = Thread(target=ssh_bruteforce_detector.run)
    t3 = Thread(target=icmp_flood.run)
    t4 = Thread(target=arp_spoof.run)
    t5 = Thread(target=mac_flood.run)
    t6 = Thread(target=revers_shell.run)
    t7 = Thread(target=icmp_tunnel.run)

    t1.start()
    t2.start()
    t3.start()
    t4.start()
    t5.start()
    t6.start()
    t7.start()

    try:
        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()
        t6.join()
        t7.join()
    except KeyboardInterrupt:
        print("\n[*] Остановка...")

if __name__ == "__main__":
    main()
