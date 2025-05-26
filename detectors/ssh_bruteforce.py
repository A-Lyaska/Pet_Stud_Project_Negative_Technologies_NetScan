import time
import re
from collections import defaultdict
from utils.logger import log_attack

class SSHBruteForceDetector:
    def __init__(self, logfile="/var/log/auth.log", threshold=5, time_window=10):
        self.logfile = logfile
        self.threshold = threshold
        self.time_window = time_window
        self.attempts = defaultdict(list)
        self.pattern = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")

    def run(self):
        print("[*] Мониторинг SSH логов активен...")
        with open(self.logfile, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                match = self.pattern.search(line)
                if match:
                    ip = match.group(1)
                    now = time.time()
                    self.attempts[ip].append(now)

                    self.attempts[ip] = [
                        ts for ts in self.attempts[ip] if now - ts <= self.time_window
                    ]

                    if len(self.attempts[ip]) >= self.threshold:
                        log_attack("SSH Brute-force обнаружен", ip)
                        self.attempts[ip].clear()
