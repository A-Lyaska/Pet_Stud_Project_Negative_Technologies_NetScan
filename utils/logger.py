import os
import json
from datetime import datetime

LOG_DIR = "log"
LOG_FILE = os.path.join(LOG_DIR, "attacks.log")

os.makedirs(LOG_DIR, exist_ok=True)

def log_attack(attack_type, source_ip):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "Время атаки": now,
        "Вид атаки": attack_type,
        "IP злоумышленника": source_ip
    }
    print(f"[{now}] [{attack_type}] from {source_ip}")
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
        f.flush()