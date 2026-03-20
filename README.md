# 🌙 PhishNyx AI

PhishNyx AI is a cybersecurity portfolio project that simulates phishing email triage in a SOC-inspired workflow.

Built with `Python` and `Streamlit`, it analyzes suspicious emails using rule-based phishing logic, URL inspection, risk scoring, and a product-style dashboard interface designed to feel closer to a real security tool than a classroom demo.

## ✨ What It Does

PhishNyx AI lets you submit an email sender, subject, and body, then evaluates the message for phishing indicators such as:

- urgent or coercive language
- credential harvesting requests
- generic greetings
- suspicious sender domains
- invoice and payment pressure
- attachment lure wording
- display-name impersonation patterns
- brand impersonation cues
- risky URLs, including shortened links and raw IP-based URLs

It then produces:

- a phishing risk score from `0–100`
- a verdict: `Low Risk`, `Suspicious`, or `Likely Phishing`
- detected red flags
- analyst-style explanation text
- recommended action guidance
- downloadable JSON reports
- recent scan history in the UI

## 🛡️ Why This Project Exists

Phishing remains one of the most common initial access vectors in real-world security incidents. This project was built to simulate how an analyst might quickly triage suspicious emails by combining:

- content-based phishing indicators
- sender reputation patterns
- URL-based risk checks
- structured recommendations
- a dashboard-first workflow

The goal is not to replace enterprise email security tooling, but to demonstrate practical detection logic, UI/UX product thinking, and security-focused application design in a portfolio-ready format.

## 🚀 Current Features

- SOC-inspired Streamlit dashboard UI
- animated cybersecurity-themed visual design
- rule-based phishing detection engine
- URL extraction and analysis
- phishing risk scoring system
- verdict classification
- red-flag and detail explanations
- analyst explanation summary
- recommended handling guidance
- built-in sample email scenarios
- recent scan history
- JSON report export

## 🔍 Detection Coverage

Current phishing checks include:

- urgent language detection
- credential request detection
- generic greeting detection
- suspicious sender domain detection
- payment and invoice pressure detection
- attachment lure detection
- display-name mismatch detection
- brand impersonation cue detection
- shortened URL detection
- raw IP-based URL detection
- suspicious URL keyword detection
- multiple URL detection

## 📁 Project Structure

```text
PhishNyx-AI/
├── app.py
├── styles.css
├── requirements.txt
├── README.md
├── core/
│   ├── analyzer.py
│   ├── indicators.py
│   ├── report.py
│   ├── scorer.py
│   └── url_checks.py
├── data/
│   └── sample_emails.json
└── utils/
```

## ⚙️ Installation

From the project root:

```powershell
pip install -r requirements.txt
```

## ▶️ Run The App

```powershell
streamlit run app.py
```

If `streamlit` is not recognized:

```powershell
python -m streamlit run app.py
```

The app usually starts at:

```text
http://localhost:8501
```

## 🧪 Sample Workflow

1. Launch the app.
2. Load one of the built-in sample scenarios or paste your own email content.
3. Click `Analyze Threat`.
4. Review the score, verdict, red flags, analyst explanation, and extracted URLs.
5. Export the result as a JSON report if needed.

## 📦 JSON Report Export

PhishNyx can export each analysis as a downloadable `.json` report containing:

- sender
- subject
- score
- verdict
- flags
- details
- recommendation
- urls_found
- url_score
- timestamp

## 🧭 Version Roadmap

### `v1.0.0`

Core phishing simulator release:

- rule-based phishing detection
- URL analysis
- scoring and verdict classification
- SOC-style dashboard UI
- JSON report export

### `v1.1`

Workflow and realism improvements:

- sample email scenarios
- analyst explanation section
- recent scans panel
- expanded phishing indicators
- smarter report naming

### `v1.2` and beyond

Planned future improvements:

- more realistic phishing datasets
- detection quality refinement
- testing and validation coverage
- richer reporting and documentation
- more advanced analyst workflow features

## 🛠️ Tech Stack

- `Python`
- `Streamlit`
- `tldextract`
- `validators`

## 📌 Portfolio Focus

This project is designed to demonstrate:

- cybersecurity problem framing
- phishing detection logic
- rule-based risk scoring
- UI/UX thinking for security tools
- modular Python project structure
- recruiter-friendly product presentation

## 📄 License

This project is licensed under the terms of the [LICENSE](LICENSE) file.
