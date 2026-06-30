# Email Analyzer

A tool that analyzes suspicious emails and produces a risk score with a plain-English explanation of what makes them dangerous.

Paste in email text or upload an `.eml` file — the analyzer runs two parallel tracks: an LLM examines the language for social engineering tactics, while traditional checks verify headers, sender domains, and embedded URLs against threat intelligence.

---

## How It Works

```
Email input (text paste or .eml file)
        │
        ├──► LLM Analysis
        │         • Urgency and fear tactics
        │         • Impersonation of trusted brands/people
        │         • Authority pressure ("IT department", "CEO", "IRS")
        │         • Requests for credentials or sensitive action
        │
        └──► Technical Analysis
                  • Header parsing (From, Reply-To, Received chain)
                  • Sender domain SPF / DKIM record verification
                  • URL extraction and VirusTotal threat intel lookup
                  • Domain age and WHOIS registration check
                        │
                        ▼
              Risk Score (0–100) + Verdict
```

---

## Features

- **Paste or upload** — accepts raw email text or `.eml` files
- **Social engineering detection** — LLM flags urgency, impersonation, authority pressure, and suspicious calls to action
- **Header analysis** — inspects `From`, `Reply-To`, and the full `Received` chain for spoofing signals
- **SPF / DKIM checks** — verifies whether the sending domain is authorized to send on behalf of the claimed identity
- **URL threat intel** — extracts all links and checks them against VirusTotal's free-tier API
- **Domain reputation** — WHOIS lookup to flag newly registered or suspicious domains
- **Risk score** — a 0–100 score where 0 is clean and 100 is almost certainly malicious
- **Plain-English verdict** — a short explanation of exactly why the email is (or isn't) suspicious

---

## Example Output

```
Risk Score: 87 / 100  🔴 HIGH RISK

Verdict:
This email exhibits multiple hallmarks of a phishing attack.

• IMPERSONATION: Claims to be from "PayPal Security Team" but was sent
  from paypa1-secure.ru — a lookalike domain registered 3 days ago.

• URGENCY: Uses phrases like "your account will be permanently suspended
  within 24 hours" to pressure the recipient into acting without thinking.

• SPF FAIL: The sending server (185.220.x.x) is not authorized to send
  email for paypal.com.

• MALICIOUS URL: The "Verify Now" link points to http://paypa1-secure.ru/login
  which VirusTotal flags as a known phishing page (14/90 engines).
```

---

## Tech Stack

| Component | Library / API |
|---|---|
| Email parsing | Python `email` stdlib + `beautifulsoup4` |
| URL extraction | `beautifulsoup4` |
| Domain analysis | `tldextract`, `python-whois` |
| SPF / DKIM | `dnspython` |
| Threat intel | VirusTotal API (free tier) |
| LLM analysis | Claude API (Anthropic) |

---

## Setup

```bash
# Clone the repo
git clone https://github.com/kanav333/email-analyzer.git
cd email-analyzer

# Install dependencies
pip install -r requirements.txt

# Set your API keys
export ANTHROPIC_API_KEY=your_key_here
export VIRUSTOTAL_API_KEY=your_key_here
```

## Usage

```bash
# Analyze a .eml file
python analyze_email.py --file suspicious.eml

# Paste email text directly
python analyze_email.py --text "Dear customer, your account has been compromised..."
```

---

## Project Status

Under active development. Core analysis modules coming soon.
