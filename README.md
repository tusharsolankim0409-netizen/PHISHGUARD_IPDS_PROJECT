# 🛡️ PhishGuard — Intelligent Phishing Detection System

> **Author:** Tushar Solanki
> **Type:** Educational Cybersecurity Prototype
> **Platform:** Windows 10/11
> **Language:** Python 3.12

---

## 📌 Project Description

**PhishGuard** is an intelligent URL analysis system that detects phishing URLs using heuristic-based structural analysis — **without ever visiting the target URL**.

Users can enter any suspicious URL and PhishGuard will:
- Analyse its structure and lexical patterns
- Compute a **risk score (0–100)**
- Classify it as **Low Risk 🟢**, **Suspicious 🟡**, or **High Risk 🔴**
- Show clear **reasons** for the classification
- Save results to a **local database**
- Allow **export** as CSV or JSON

> ⚠️ **Disclaimer:** PhishGuard is a heuristic-based educational tool. It can produce false positives and false negatives and **cannot guarantee** any URL is safe or malicious. This is **not** a production security product.

---

## 🎯 Problem Statement

Traditional phishing detection relies on blacklists that fail against newly created phishing domains. A user receiving an unknown URL has no safe way to assess it without visiting it — which is itself dangerous.

PhishGuard solves this by performing **fully offline structural analysis** before any network request is made.

---

## ✅ Key Features

| Feature | Description |
|---|---|
| 🔍 URL Scanner | Analyse any URL without visiting it |
| 📊 Risk Scoring | Heuristic score 0–100 with 14 rules |
| 🏷️ Classification | Low Risk / Suspicious / High Risk |
| 💡 Explanations | Human-readable reasons for every verdict |
| 🌐 Threat Intel | Optional VirusTotal API integration |
| 🗄️ Scan History | Persisted in local SQLite database |
| 📥 Export | Download history as CSV or JSON |
| 📈 Dashboard | Live statistics and scan history table |
| 🔒 Privacy | No credentials collected, no URLs visited |

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.12 | Core programming language |
| Flask 2.x | Web framework (UI + REST API) |
| SQLite3 | Local scan history database |
| urllib.parse | URL parsing |
| re (Regex) | Pattern matching |
| hashlib | Unique scan ID generation |
| json / csv | Data export |
| requests *(optional)* | VirusTotal API calls |
| HTML / CSS / JavaScript | Frontend dashboard (inline, no CDN) |
| unittest | Automated testing (in notebook) |

---

## 📁 Project Files

```
PHISHGUARD. IPYNB/
│
├── app.py                          # Main Flask web application
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── start.bat                       # One-click startup script (Windows)
├── start.ps1                       # PowerShell startup script
├── Tushar_Solanki_PhishGuard.ipynb # Jupyter Notebook version
├── PhishGuard_Report.docx          # Complete project report
└── phishguard_history.db           # SQLite database (auto-created on first run)
```

---

## ⚙️ Setup & Installation

### Requirements
- Python 3.9 or higher (Python 3.12 recommended)
- Windows 10 / 11

### Step 1 — Install Python
Download from: **https://python.org/downloads**
> ✅ Make sure to tick **"Add Python to PATH"** during installation

### Step 2 — Open Terminal in Project Folder
1. Open the `PHISHGUARD. IPYNB` folder
2. Click the address bar → type `cmd` → press Enter

### Step 3 — Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Run the Application
```bash
python app.py
```

### Step 5 — Open in Browser
```
http://localhost:8080
```

> 💡 **Shortcut:** Double-click `start.bat` — it installs Flask and starts the server automatically.

---

## 🚀 How to Use

1. Open `http://localhost:8080` in Chrome/Edge/Firefox
2. Enter any URL in the scanner box
3. Click **Scan** or press **Enter**
4. View the risk verdict, score, and reasons
5. Check the **Dashboard** for statistics
6. Export history using **Export CSV** or **Export JSON** buttons

---

## 📊 Risk Score Guide

| Score | Label | Colour | Meaning |
|---|---|---|---|
| 0 – 39 | Low Risk | 🟢 Green | Few or no risk indicators |
| 40 – 69 | Suspicious | 🟡 Yellow | Some indicators; be cautious |
| 70 – 100 | High Risk | 🔴 Red | Multiple strong indicators |

> ⚠️ The score is a **heuristic index**, NOT a probability percentage.

---

## 🧪 Sample Test URLs

| URL | Expected Result |
|---|---|
| `https://www.google.com` | 🟢 Low Risk |
| `http://paypal-account-verify.com/login` | 🟡 Suspicious |
| `http://192.168.1.1/paypal/login/verify` | 🔴 High Risk |

---

## 🌐 REST API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Web dashboard UI |
| `/api/scan` | POST | Scan a URL |
| `/api/history` | GET | Get scan history |
| `/api/history` | DELETE | Clear scan history |
| `/api/stats` | GET | Get statistics |
| `/api/export/csv` | GET | Download CSV |
| `/api/export/json` | GET | Download JSON |
| `/api/health` | GET | Health check |

---

## 🔒 Security & Privacy

- ✅ Scanned URLs are **never visited or fetched**
- ✅ No passwords or credentials are ever collected
- ✅ All data stored **locally only** (SQLite on your machine)
- ✅ API key read from environment variable — never logged
- ✅ `javascript:` and `data:` URIs are rejected immediately

---

## ⚠️ Limitations

- Heuristic-based — not ML-based; false positives/negatives are possible
- Cannot inspect page content (URL is never visited)
- Newly registered clean-looking domains may score Low Risk even if malicious
- Educational prototype only — not for production use

---

## 🔭 Future Scope

- Machine Learning classifier (Random Forest / XGBoost)
- WHOIS domain age lookup
- Browser extension (Chrome/Firefox)
- Email URL scanner
- Multi-language keyword support

---

## 📚 References

1. Anti-Phishing Working Group — https://apwg.org
2. VirusTotal API v3 — https://developers.virustotal.com
3. Python urllib.parse — https://docs.python.org/3/library/urllib.parse.html
4. Flask Documentation — https://flask.palletsprojects.com
5. PhishTank Dataset — https://www.phishtank.com
6. OpenPhish Feed — https://openphish.com

---

## 📄 License

This project is created for **educational purposes only** as part of an academic submission.

---

*PhishGuard — Intelligent Phishing Detection System | Author: Tushar Solanki*
