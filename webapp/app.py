from flask import Flask, render_template, jsonify, request
import json

app = Flask(__name__)

LOG_FILE = "../logs/attacks.log"

def load_attacks():
    attacks = []
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                attacks.append(json.loads(line.strip()))
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
    data = load_attacks()
    if attack_type and attack_type != "all":
        data = [a for a in data if a["type"] == attack_type]
    return jsonify(data)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
