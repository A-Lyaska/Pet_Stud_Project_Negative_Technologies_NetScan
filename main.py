from detectors.portscan import PortScanDetector
from utils.logger import log_attack
from detectors.ssh_bruteforce import SSHBruteForceDetector

def main():
    print("[*] NT_NetScan запущен...")
    detector = PortScanDetector()
    ssh_brutefroce = SSHBruteForceDetector()
    try:
        detector.run()
        ssh_brutefroce.run()
    except KeyboardInterrupt:
        print("\n[*] Остановка...")

if __name__ == "__main__":
    main()
