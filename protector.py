import os
import json
import time
import random
import string
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

API_KEY = os.getenv("API_KEY", "")
if not API_KEY:
    raise RuntimeError("API_KEY environment variable is not set")

DB_PATH = os.getenv("DB_PATH", "webhooks.json")

RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW = 60
rate_limit_store = {}

DISCORD_PREFIXES = [
    "https://discord.com/api/webhooks/",
    "https://discordapp.com/api/webhooks/",
    "https://ptb.discord.com/api/webhooks/",
    "https://canary.discord.com/api/webhooks/",
]

ALLOWED_KEYWORDS = ["🎒 Inventory", "🛒 Total Items"]


def load_db():
    if os.path.exists(DB_PATH):
        try:
            with open(DB_PATH, "r") as f:
                return json.load(f)
        except:
            pass
    return {}


def save_db(data):
    with open(DB_PATH, "w") as f:
        json.dump(data, f, indent=2)


db = load_db()


def is_rate_limited(ip):
    now = time.time()
    if ip not in rate_limit_store:
        rate_limit_store[ip] = []
    rate_limit_store[ip] = [t for t in rate_limit_store[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(rate_limit_store[ip]) >= RATE_LIMIT_MAX:
        return True
    rate_limit_store[ip].append(now)
    return False


def is_discord_webhook(url):
    return any(url.startswith(p) for p in DISCORD_PREFIXES)


def payload_matches_filter(payload):
    if not isinstance(payload, dict):
        return False
    content = payload.get("content", "")
    if any(kw in content for kw in ALLOWED_KEYWORDS):
        return True
    embeds = payload.get("embeds") or []
    for embed in embeds:
        parts = [
            embed.get("title", ""),
            embed.get("description", ""),
            embed.get("author", {}).get("name", ""),
            embed.get("footer", {}).get("text", ""),
        ]
        for field in embed.get("fields") or []:
            parts.append(field.get("name", ""))
            parts.append(field.get("value", ""))
        combined = " ".join(parts)
        if any(kw in combined for kw in ALLOWED_KEYWORDS):
            return True
    return False


@app.route("/", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "Discord Webhook Protector Proxy",
        "webhooks": len(db),
        "uptime": int(time.time()),
    })


@app.route("/protect", methods=["POST"])
def protect_webhook():
    api_key = request.headers.get("X-API-Key", "")
    if api_key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    if is_rate_limited(request.remote_addr):
        return jsonify({"error": "Too Many Requests"}), 429

    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field"}), 400

    url = data["url"]
    if not is_discord_webhook(url):
        return jsonify({"error": "Invalid Discord webhook URL"}), 400

    existing = next(((k, v) for k, v in db.items() if v["real_url"] == url), None)
    if existing:
        return jsonify({
            "protected_url": f"{request.host_url}webhook/{existing[0]}",
            "id": existing[0],
            "created_at": existing[1]["created_at"],
            "message": "Already registered",
        })

    uid = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    db[uid] = {
        "real_url": url,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "stats": {"forwarded": 0, "filtered": 0, "errors": 0},
    }
    save_db(db)

    return jsonify({
        "protected_url": f"{request.host_url}webhook/{uid}",
        "id": uid,
        "created_at": db[uid]["created_at"],
        "message": "Webhook registered",
    }), 201


@app.route("/webhooks", methods=["GET"])
def list_webhooks():
    api_key = request.headers.get("X-API-Key", "")
    if api_key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({
        "count": len(db),
        "webhooks": [
            {"id": uid, "protected_url": f"{request.host_url}webhook/{uid}", "created_at": meta["created_at"], "stats": meta["stats"]}
            for uid, meta in db.items()
        ],
    })


@app.route("/webhooks/<uid>", methods=["DELETE"])
def delete_webhook(uid):
    api_key = request.headers.get("X-API-Key", "")
    if api_key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    if uid not in db:
        return jsonify({"error": "Not found"}), 404

    del db[uid]
    save_db(db)
    return jsonify({"success": True})


@app.route("/webhook/<uid>", methods=["POST"])
def handle_webhook(uid):
    if is_rate_limited(request.remote_addr):
        return jsonify({"error": "Too Many Requests"}), 429

    if uid not in db:
        return jsonify({"error": "Not found"}), 404

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid payload"}), 400

    if not payload_matches_filter(payload):
        db[uid]["stats"]["filtered"] += 1
        save_db(db)
        return jsonify({"success": True, "forwarded": False, "reason": "Filtered"}), 200

    try:
        resp = requests.post(
            db[uid]["real_url"],
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
    except requests.RequestException as e:
        db[uid]["stats"]["errors"] += 1
        save_db(db)
        return jsonify({"error": f"Forward failed: {str(e)}"}), 502

    db[uid]["stats"]["forwarded"] += 1
    save_db(db)

    if resp.status_code == 204:
        return "", 204
    try:
        return jsonify(resp.json()), resp.status_code
    except:
        return jsonify({"status": "forwarded", "discord_code": resp.status_code}), resp.status_code


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] 🚀 Webhook proxy running on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
