import os
import json
from datetime import datetime

LOG_DIR = "log"
LOG_FILE = os.path.join(LOG_DIR, "attacks.json")

os.makedirs(LOG_DIR, exist_ok=True)

def log_attack(attack_type, ip, details):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "Date attack": now,
        "Type attack": attack_type,
        "Badboy's IP": ip,
        "Details": details
    }
    with open("log/attacks.json", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    print(f"[{now}] [{attack_type}] from {ip} - {details}")

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
        f.flush()