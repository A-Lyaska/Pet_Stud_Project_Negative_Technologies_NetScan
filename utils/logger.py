import os
import json
from datetime import datetime

LOG_DIR = "log"
LOG_FILE = os.path.join(LOG_DIR, "attacks.json")

os.makedirs(LOG_DIR, exist_ok=True)

def log_attack(attack_type, details, ip):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    record = {
        "Date attack": now,
        "Type attack": attack_type,
        "Details": details,
        "Badboy's IP": ip
    }
    with open("log/attacks.json", "a") as f:
        f.write(json.dumps(record) + "\n")

    print(f"[{now}] [{attack_type}] from {ip} - {details}")
    
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
        f.flush()
