from flask import Flask, render_template, request
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Transparent, rule-based demo checks. This is not a trained AI model or live threat-intelligence service.
URGENT_TERMS = [
    "urgent", "immediately", "act now", "within 24 hours", "account suspended",
    "verify your account", "limited time", "final warning", "unusual activity"
]
SENSITIVE_TERMS = [
    "password", "otp", "one-time password", "pin number", "bank details",
    "credit card", "login details", "verification code"
]
PRIZE_TERMS = [
    "you won", "winner", "claim your prize", "free gift", "congratulations",
    "cash reward", "giveaway"
]
PAYMENT_TERMS = [
    "transfer money", "send money", "pay a fee", "processing fee",
    "gift card", "crypto payment"
]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rebrand.ly"}
URL_RE = re.compile(r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)", re.I)


def analyze_message(message):
    text = message.lower()
    score = 0
    findings = []

    def add_finding(label, points, explanation):
        nonlocal score
        score += points
        findings.append({"label": label, "points": points, "explanation": explanation})
    urgent_found = [term for term in URGENT_TERMS if term in text]
    sensitive_found = [term for term in SENSITIVE_TERMS if term in text]
    prize_found = [term for term in PRIZE_TERMS if term in text]
    payment_found = [term for term in PAYMENT_TERMS if term in text]

    if urgent_found:
        add_finding("Pressure or urgency", 22,
                    "The message uses urgent language that may pressure you into acting quickly.")
    if sensitive_found:
        add_finding("Sensitive information request", 32,
                    "It mentions credentials, codes, or financial details. Never share these through an unexpected message.")
    if prize_found:
        add_finding("Prize or reward claim", 18,
                    "Unexpected prizes or rewards can be used to lure people into clicking links or paying fees.")
    if payment_found:
        add_finding("Payment request", 24,
                    "The message mentions a payment or transfer. Verify the request through an official channel.")

    urls = URL_RE.findall(message)
    for raw_url in urls:
        cleaned = raw_url.rstrip(".,);!?]")
        candidate = cleaned if cleaned.lower().startswith(("http://", "https://")) else "http://" + cleaned
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        if parsed.scheme == "http":
            add_finding("Unencrypted HTTP link", 12,
                        f"The link to {host} uses HTTP rather than HTTPS. This alone does not prove it is a scam.")
        if host in SHORTENERS:
            add_finding("Shortened link", 18,
                        f"The destination of {host} is hidden. Avoid opening it unless you can verify it independently.")
        if host.startswith("xn--") or ".xn--" in host:
            add_finding("Internationalized domain", 20,
                        "This domain uses an encoded internationalized label. Check the spelling carefully.")
        if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            add_finding("IP-address link", 22,
                        "The link uses an IP address instead of a familiar domain. Verify it before visiting.")

    # Cap the score so the display remains a simple, understandable indicator.
    score = min(score, 100)
    if score >= 55:
        level, label, color = "high", "High risk", "red"
        summary = "This message contains several warning signs. Do not click links or share information."
    elif score >= 25:
        level, label, color = "medium", "Medium risk", "amber"
        summary = "Be cautious. Verify the sender and any request through an official channel."
    else:
        level, label, color = "low", "Lower risk", "green"
        summary = "Few predefined warning signs were detected. This does not guarantee the message is safe."

    if not findings:
        findings.append({
            "label": "No matching warning signs",
            "points": 0,
            "explanation": "The demo did not find any of its predefined indicators. Scams can still look convincing."
        })

    tips = [
        "Do not share passwords, PINs, or one-time passcodes with anyone.",
        "Open the official app or type the official website address yourself instead of using an unexpected link.",
        "Contact the organisation using a phone number or contact method you already trust.",
        "If you already shared banking details, contact your bank promptly using its official number."
    ]

    return {
        "score": score,
        "level": level,
        "label": label,
        "color": color,
        "summary": summary,
        "findings": findings,
        "tips": tips,
        "url_count": len(urls)
    }


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    message = ""
    if request.method == "POST":
        message = request.form.get("message", "").strip()
        if message:
            result = analyze_message(message)
        else:
            result = {"error": "Paste a message or link first."}
    return render_template("index.html", result=result, message=message)


@app.route("/health")
def health():
    return {"status": "ok", "service": "CyberShield AI demo", "analysis": "rule-based"}



if __name__ == "__main__":
    # For local development only. Use a production WSGI server when deploying publicly.
    app.run(host="0.0.0.0", port=5000, debug=True)

