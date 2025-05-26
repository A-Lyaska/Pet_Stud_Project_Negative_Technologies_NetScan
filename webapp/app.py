from flask import Flask, render_template, jsonify, request
import json

app = Flask(__name__)

LOG_FILE = "log/attacks.json"

def load_attacks():
    attacks = []
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                raw = json.loads(line.strip())
                attack = {
                    "time": raw.get("Date attack", ""),
                    "type": raw.get("Type attack", ""),
                    "ip": raw.get("Badboy's IP", ""),
                    "details": raw.get("Details", "")
                }
                attacks.append(attack)
        attacks.reverse()
    except FileNotFoundError:
        pass
    return attacks


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/logs")
def logs():
    attack_type = request.args.get("type")
    raw_data = load_attacks()
    result = []

    for a in raw_data:
        a_type = a.get("type", "")
        a_ip = a.get("ip", "")
        a_time = a.get("time", "")
        a_details = a.get("details", "")

        if attack_type and attack_type != "all":
            if attack_type != a_type:
                continue

        result.append({
            "type": a_type,
            "ip": a_ip,
            "time": a_time,
            "details": a_details
        })

    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
