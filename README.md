# 🛡️ NeuralPhish — AI Phishing & Messenger URL Security Shield

> **Enterprise-Grade, Privacy-First Phishing Detection for WhatsApp, Email, SMS, and Web Browsing.**  
> Runs 100% locally on your own computer with zero cloud telemetry.

---

## 🌟 Why NeuralPhish?

When someone sends you an urgent email, WhatsApp message, or SMS claiming:
- *"Your Netflix account has been suspended, update your payment here..."*
- *"You won an Amazon $1,000 gift card, claim here..."*
- *"Your bank KYC has expired, click to renew or your account will be blocked..."*
- *"FedEx parcel delivery failed, pay $1.50 redelivery fee here..."*

**NeuralPhish protects you immediately.** It extracts every hidden, defanged, or obfuscated link, performs hybrid machine learning & lexical analysis, detects **Brand Impersonation**, and gives you a clear verdict: **DANGEROUS**, **SUSPICIOUS**, or **SAFE**, with actionable advice on what to do.

---

## ⚡ 1-Click Installation on Your System

### Prerequisites
- Windows 10 / 11 (or Linux / macOS)
- Python 3.8 to 3.12 installed ([Download Python](https://python.org) and check *"Add Python to PATH"* during setup).

### Installation Steps
1. Open this folder: `C:\Personal files\NeuralPhish`
2. **Double-click `install.bat`**  
   - Automatically installs required dependencies (`flask`, `scikit-learn`, `nltk`, `pyperclip`, `requests`, `pillow`).
   - Downloads tokenizers and verifies trained models (`phising.pkl`, `vectorizer.pkl`).
3. *(Optional)* **Double-click `create_desktop_shortcuts.bat`** to put 1-click launch shortcuts right on your Windows Desktop!

---

## 🚀 3 Easy Ways to Check Messages on Your System

### Method 1: Web Security Dashboard (Visual & Interactive)
1. **Double-click `run.bat`** (or run `python app.py`).
2. Your browser will automatically open to `http://127.0.0.1:5000`.
3. Go to the **"💬 Messenger & Email Scanner"** tab.
4. Paste the entire message you received (from WhatsApp, Outlook, Gmail, or SMS).
5. Click **"Analyze Message & Links"** (or click *"Paste from Clipboard & Scan"*).
6. **Result:** Instantly shows:
   - Overall Verdict (**DANGEROUS** / **SUSPICIOUS** / **SAFE**)
   - Risk Score ($0 - 100$)
   - Brand Impersonation Alerts (e.g. *"Message claims to be from Netflix, but the destination link is on an unverified domain!"*)
   - Extracted links with individual safety scores
   - Step-by-step guidance (*"Do not click, block sender, do not share OTP"*).

---

### Method 2: Desktop Clipboard Sentinel (Automatic Real-Time Protection)
*Want automatic alerts while chatting on WhatsApp or reading emails without opening any browser?*

1. **Double-click `run_messenger_guard.bat`** (or run `python messenger_guard.py`).
2. Minimize the window to let it run quietly in the background.
3. **How it works:**
   - Whenever you copy any message or link (`Ctrl+C`) in **WhatsApp Desktop**, **WhatsApp Web**, **Outlook**, **Thunderbird**, or **Telegram**:
   - NeuralPhish scans it in milliseconds.
   - If a malicious link or phishing trap is found, it immediately pops up a **native Windows Toast Notification** and plays a warning alert chime!
   - Logged automatically to `threats_detected.log`.

---

### Method 3: Browser Extension (For WhatsApp Web, Gmail & Outlook)
*Right-click scanning directly inside your web browser.*

1. In Chrome, Edge, or Brave, open:
   ```
   chrome://extensions  (or edge://extensions)
   ```
2. Turn **ON** the switch for **"Developer mode"** in the top right.
3. Click **"Load unpacked"** and select:
   ```
   C:\Personal files\NeuralPhish\NeuralPhish\extension
   ```
4. **Usage:**
   - **Right-click any link** in WhatsApp Web or an email -> **"🛡️ Scan Link with NeuralPhish"**.
   - **Highlight any message text** -> **"🛡️ Scan Message with NeuralPhish"**.
   - A browser notification will appear instantly with the threat assessment.

---

### Method 4: Terminal / CLI Scanner
For power users and command line checks:
```bash
# Scan a single URL
python cli.py https://example-suspicious-site.xyz

# Scan an unstructured email or chat message
python cli.py --message "Urgent PayPal verification required at http://paypal-update.xyz/login"

# Interactive prompt (paste messages anytime)
python cli.py --interactive
```

---

## 🧠 Detection Architecture & Technical Highlights

NeuralPhish leverages a **Defense-in-Depth** multi-layer evaluation pipeline:

| Layer | Mechanism | Purpose |
|---|---|---|
| **Layer 1** | **URL Normalization & Defang Recovery** | Restores `hxxp://`, `example[.]com`, and extracts schemeless domains (`bit.ly`, `domain.top/login`). |
| **Layer 2** | **Social Engineering Analysis** | Detects psychological urgency lures (*"suspended within 24 hours"*, *"final notice"*), credential theft triggers (*"verify OTP"*, *"kyc update"*), and financial bait (*"won lottery"*, *"unpaid invoice"*). |
| **Layer 3** | **Brand Impersonation Correlation** | Cross-references brand mentions (Netflix, WhatsApp, PayPal, Apple, Amazon, SBI, FedEx, DHL, USPS, etc.) against official registered domains. Flags mismatches as high-confidence phishing. |
| **Layer 4** | **NLP Machine Learning Inference** | Uses `RegexpTokenizer([A-Za-z]+)`, `SnowballStemmer("english")`, `CountVectorizer`, and a trained `MultinomialNB` model (96.56% benchmark accuracy on 549,346 URLs). |
| **Layer 5** | **Cybersecurity Heuristics & Entropy** | Calculates Shannon Entropy (detects algorithmic DGA domains), checks for raw IP hosts, Punycode/IDN homographs, suspicious TLDs (`.xyz`, `.top`, `.buzz`, `.cf`, etc.), and port anomalies. |

---

## 📡 REST API Reference

The local server exposes RESTful endpoints at `http://127.0.0.1:5000`:

### `POST /api/scan-message`
Scans raw text from emails, WhatsApp chats, or SMS.
```json
// Request
{
  "message": "Urgent: Your Netflix payment has failed. Update at https://netflix-billing-renew.xyz/login within 24h"
}

// Response
{
  "success": true,
  "data": {
    "verdict": "DANGEROUS",
    "status": "danger",
    "risk_score": 100.0,
    "summary": "Phishing / Scam Alert: Detected 1 link(s)...",
    "urls_found": 1,
    "extracted_urls": ["https://netflix-billing-renew.xyz/login"],
    "social_engineering": {
      "has_brand_impersonation": true,
      "urgency_triggers": ["urgent", "within 24 hours"],
      "impersonation_flags": [
        {
          "brand": "Netflix",
          "warning": "Message claims to be from Netflix, but destination link does NOT match any official Netflix domain."
        }
      ]
    },
    "recommendations": [
      "DO NOT CLICK or tap any of the links in this message.",
      "Never submit passwords or OTPs.",
      "Block and report the sender."
    ]
  }
}
```

### `POST /api/scan`
Scans a single URL string.
```json
// Request
{ "url": "https://example.com" }
```

### `POST /api/batch-scan`
Batch scan up to 50 URLs in one request.
```json
// Request
{ "urls": ["https://google.com", "http://bad-link.xyz"] }
```

### `GET /api/health`
Checks server and engine status.

---

## 📂 Project Directory Structure

```
NeuralPhish/
├── install.bat                     # 1-Click automated installer
├── run.bat                         # 1-Click web dashboard launcher
├── run_messenger_guard.bat         # 1-Click clipboard WhatsApp sentinel
├── run_cli.bat                     # 1-Click interactive terminal scanner
├── create_desktop_shortcuts.bat    # Creates Windows Desktop shortcuts
├── requirements.txt                # Pinned dependencies
├── README.md                       # Comprehensive guide
└── NeuralPhish/
    ├── app.py                      # Flask REST API & Web Server
    ├── index.html                  # Cyberpunk dark-mode web UI
    ├── scanner_engine.py           # Hybrid ML + lexical heuristic engine
    ├── message_engine.py           # Social engineering & WhatsApp/email analyzer
    ├── messenger_guard.py          # Real-time background clipboard monitor
    ├── cli.py                      # Terminal scanning utility
    ├── phising.pkl                 # Serialized Naive Bayes model
    ├── phising_mnb.pkl             # MultinomialNB model backup
    ├── vectorizer.pkl              # CountVectorizer feature extractor
    └── extension/                  # Chrome / Edge Browser Extension
        ├── manifest.json           # Manifest V3 configuration
        ├── background.js           # Right-click context menu handler
        ├── popup.html              # Extension toolbar popup
        ├── popup.js                # Extension popup logic
        ├── README_EXTENSION.md     # Extension setup guide
        └── icons/                  # 16px, 48px, 128px shield icons
```

---

## 🔒 Privacy & Safety Guarantee
- All scans execute on your local CPU.
- Your personal emails, WhatsApp chats, and copied messages **never leave your machine**.
- Works completely **offline** without internet access after initial dependency installation.
