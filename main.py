from detectors.portscan import PortScanDetector
from utils.logger import log_attack

def main():
    print("[*] Network Attack Detector запущен...")
    detector = PortScanDetector()
    try:
        detector.run()
    except KeyboardInterrupt:
        print("\n[*] Остановка...")

if __name__ == "__main__":
    main()
