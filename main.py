from threading import Thread
from detectors.portscan import PortScanDetector
from detectors.ssh_bruteforce import SSHBruteForceDetector

def main():
    print("[*] NT_NetScan запущен...")

    portscan_detector = PortScanDetector()
    ssh_bruteforce_detector = SSHBruteForceDetector()

    t1 = Thread(target=portscan_detector.run)
    t2 = Thread(target=ssh_bruteforce_detector.run)

    t1.start()
    t2.start()

    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        print("\n[*] Остановка...")

if __name__ == "__main__":
    main()
