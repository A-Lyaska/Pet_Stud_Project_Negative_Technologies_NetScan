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
                    "ip": raw.get("Badboy's IP", "")
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
    attack_type = request.args.get("type", "all")
    data = load_attacks()
    if attack_type.lower() != "all":
        data = [a for a in data if a["type"].lower() == attack_type.lower()]
    return jsonify(data)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
