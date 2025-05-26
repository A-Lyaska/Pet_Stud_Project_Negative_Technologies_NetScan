import json
import os
from datetime import datetime

LOG_FILE = "logs/attacks.log"

def log_attack(attack_type, source_ip):
    log_entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": attack_type,
        "ip": source_ip
    }

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")