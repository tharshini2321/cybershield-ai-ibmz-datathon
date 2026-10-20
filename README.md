# CyberShield AI — Enhanced Flask Prototype

A polished, responsive cybersecurity-awareness demo built with Python and Flask.

## Features
- Responsive landing page and dashboard styling
- Rule-based checks for urgency, sensitive-information requests, prize claims, payment requests, shortened URLs, HTTP links, and some suspicious URL patterns
- Indicative risk score, explanations, and safety recommendations
- Sample messages for quick demonstrations
- `/health` endpoint for a simple health check

## Run on Windows
1. Open Command Prompt in this folder.
2. Create a virtual environment (if you don't already have one):
   ```bat
   python -m venv .venv
   ```
3. Activate it:
   ```bat
   .venv\Scripts\activate
   ```
4. Install dependencies:
   ```bat
   pip install -r requirements.txt
   ```
5. Start the app:
   ```bat
   python app.py
   ```
6. Open `http://127.0.0.1:5000`.

## Project structure
```text
CyberShield_AI_Enhanced/
├── app.py
├── requirements.txt
├── README.md
└── templates/
    └── index.html
```

## Important limitations
This is a transparent, rule-based prototype. It does not use a trained AI model, live threat-intelligence feeds, or a confirmed IBM Z integration. Scores are indicative only and cannot guarantee that a message is safe or fraudulent. Do not submit real passwords, OTPs, or private financial information into the demo.

## Before public deployment
Use a production WSGI server, configure a secure deployment, disable debug mode, review privacy and logging, add tests, and validate the detection logic. Do not expose Flask's development server publicly.
