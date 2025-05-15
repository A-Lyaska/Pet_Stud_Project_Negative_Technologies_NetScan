from threading import Thread
from detectors.portscan import PortScanDetector
from detectors.ssh_bruteforce import SSHBruteForceDetector
from utils.logger import log_attack

def main():
    print("[*] NT_NetScan запущен...")

    portscan_detector = PortScanDetector(iface="ens33")
    ssh_detector = SSHBruteForceDetector()

    t1 = Thread(target=portscan_detector.run)
    t2 = Thread(target=ssh_detector.run)

    t1.start()
    t2.start()

    t1.join()
    t2.join()

if __name__ == "__main__":
    main()
