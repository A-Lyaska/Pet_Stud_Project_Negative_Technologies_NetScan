import os
from datetime import datetime

LOG_DIR = "log"
LOG_FILE = os.path.join(LOG_DIR, "attacks.log")

os.makedirs(LOG_DIR, exist_ok=True)

def log_attack(attack_type, source_ip):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"[{now}] [{attack_type}] from {source_ip}"
    print(message)
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")
