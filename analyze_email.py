import sys
import os
import re
import json
import base64
import time
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse
from datetime import datetime, timezone

from bs4 import BeautifulSoup
import tldextract
import whois
import requests
from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()


SUSPICIOUS_BRANDS = [
    "paypal.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "netflix.com",
    "purdue.edu",
    "github.com",
]


def load_email(file_path):
    """Load and parse a .eml file."""
    with open(file_path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def get_basic_headers(msg):
    """Extract important email headers."""
    return {
        "From": msg.get("From", ""),
        "Reply-To": msg.get("Reply-To", ""),
        "To": msg.get("To", ""),
        "Subject": msg.get("Subject", ""),
        "Date": msg.get("Date", ""),
        "Message-ID": msg.get("Message-ID", ""),
        "Return-Path": msg.get("Return-Path", ""),
        "Authentication-Results": msg.get("Authentication-Results", ""),
        "Received-SPF": msg.get("Received-SPF", ""),
    }


def extract_email_domain(header_value):
    """Extract domain from an email header like 'Name <user@example.com>'."""
    _, email_addr = parseaddr(header_value)

    if "@" not in email_addr:
        return ""

    return email_addr.split("@")[-1].lower()


def check_from_reply_to_mismatch(from_header, reply_to_header):
    """Check if From and Reply-To domains are different."""
    if not reply_to_header:
        return False, "No Reply-To header found."

    from_domain = extract_email_domain(from_header)
    reply_to_domain = extract_email_domain(reply_to_header)

    if not from_domain or not reply_to_domain:
        return False, "Could not extract one or both domains."

    if from_domain != reply_to_domain:
        return True, f"From domain ({from_domain}) differs from Reply-To domain ({reply_to_domain})."

    return False, "From and Reply-To domains match."


def extract_body(msg):
    """Extract plain text and HTML body from the email."""
    plain_text = ""
    html_text = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = part.get_content_disposition()

            # Skip attachments
            if content_disposition == "attachment":
                continue

            try:
                content = part.get_content()
            except Exception:
                continue

            if content_type == "text/plain":
                plain_text += str(content)
            elif content_type == "text/html":
                html_text += str(content)
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            content = ""

        if content_type == "text/plain":
            plain_text = str(content)
        elif content_type == "text/html":
            html_text = str(content)

    return plain_text, html_text


def extract_urls_from_text(text):
    """Extract URLs from plain text using regex."""
    url_pattern = r"https?://[^\s<>\"]+"
    return re.findall(url_pattern, text)


def extract_urls_from_html(html):
    """Extract URLs from HTML using BeautifulSoup."""
    urls = []

    if not html:
        return urls

    soup = BeautifulSoup(html, "html.parser")

    for tag in soup.find_all(["a", "img", "script", "iframe"]):
        for attr in ["href", "src"]:
            value = tag.get(attr)
            if value and value.startswith(("http://", "https://")):
                urls.append(value)

    return urls


def get_registered_domain(value):
    """Extract registered domain from a URL or domain."""
    extracted = tldextract.extract(value)

    if not extracted.domain or not extracted.suffix:
        return ""

    return f"{extracted.domain}.{extracted.suffix}".lower()


def parse_authentication_results(auth_header, received_spf):
    """Find SPF, DKIM, and DMARC results from headers."""
    combined = f"{auth_header} {received_spf}".lower()

    results = {
        "SPF": "not found",
        "DKIM": "not found",
        "DMARC": "not found",
    }

    spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", combined)
    dkim_match = re.search(r"dkim=(pass|fail|neutral|none|temperror|permerror)", combined)
    dmarc_match = re.search(r"dmarc=(pass|fail|bestguesspass|none|temperror|permerror)", combined)

    if spf_match:
        results["SPF"] = spf_match.group(1)

    if dkim_match:
        results["DKIM"] = dkim_match.group(1)

    if dmarc_match:
        results["DMARC"] = dmarc_match.group(1)

    return results


def get_domain_age(domain):
    """Use WHOIS to estimate domain age."""
    try:
        data = whois.whois(domain)
        creation_date = data.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return "unknown", "No creation date found."

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days

        return age_days, f"Domain created on {creation_date.date()}."

    except Exception as e:
        return "unknown", f"WHOIS lookup failed: {e}"


def levenshtein_distance(a, b):
    """Calculate edit distance between two strings."""
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]

    for i in range(len(a) + 1):
        dp[i][0] = i

    for j in range(len(b) + 1):
        dp[0][j] = j

    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1

            dp[i][j] = min(
                dp[i - 1][j] + 1,        # deletion
                dp[i][j - 1] + 1,        # insertion
                dp[i - 1][j - 1] + cost  # substitution
            )

    return dp[-1][-1]


def check_lookalike_domain(domain):
    """Check whether a domain looks similar to common trusted brands."""
    warnings = []

    if not domain:
        return warnings

    for brand in SUSPICIOUS_BRANDS:
        distance = levenshtein_distance(domain, brand)

        # Distance 1 or 2 can catch things like paypa1.com vs paypal.com
        if domain != brand and distance <= 2:
            warnings.append(f"{domain} looks similar to {brand}")

    return warnings


LLM_MODEL = "gemini-2.5-flash"

LLM_SCHEMA = {
    "type": "object",
    "properties": {
        "urgency_or_fear_tactics": {"type": "boolean"},
        "impersonation": {"type": "boolean"},
        "authority_pressure": {"type": "boolean"},
        "requests_credentials_or_action": {"type": "boolean"},
        "summary": {"type": "string"},
    },
    "required": [
        "urgency_or_fear_tactics",
        "impersonation",
        "authority_pressure",
        "requests_credentials_or_action",
        "summary",
    ],
}


def analyze_with_llm(subject, plain_text, html_text):
    """Ask Gemini to flag social-engineering tactics in the email body."""
    api_key = os.environ.get("GEMINI_API_KEY")

    if not api_key:
        return None, "GEMINI_API_KEY not set; skipping LLM analysis."

    body = plain_text
    if not body and html_text:
        body = BeautifulSoup(html_text, "html.parser").get_text()
    body = (body or "").strip()[:8000]

    prompt = (
        "Analyze this email for phishing and social engineering tactics.\n\n"
        f"Subject: {subject}\n\nBody:\n{body}"
    )

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=LLM_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_json_schema=LLM_SCHEMA,
            ),
        )
    except Exception as e:
        return None, f"LLM analysis failed: {e}"

    try:
        return json.loads(response.text), None
    except (json.JSONDecodeError, TypeError):
        return None, "LLM analysis failed: could not parse response."


VT_BASE_URL = "https://www.virustotal.com/api/v3"


def check_url_virustotal(url, api_key):
    """Look up a URL's VirusTotal verdict (free-tier v3 API)."""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers, timeout=15)
    except requests.RequestException as e:
        return {"status": "error", "message": str(e)}

    if resp.status_code == 200:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "status": "found",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total_engines": sum(stats.values()),
        }

    if resp.status_code == 404:
        # No scan history yet — submit it for future analysis, don't block waiting.
        try:
            requests.post(f"{VT_BASE_URL}/urls", headers=headers, data={"url": url}, timeout=15)
        except requests.RequestException:
            pass
        return {"status": "not_scanned"}

    if resp.status_code == 429:
        return {"status": "error", "message": "VirusTotal rate limit exceeded."}

    return {"status": "error", "message": f"VirusTotal returned HTTP {resp.status_code}."}


def print_report(headers, auth_results, mismatch_result, urls, sender_domain, domain_age, lookalike_warnings,
                  llm_result, llm_error, url_reports):
    """Print a structured report."""
    print("=" * 60)
    print("EMAIL SECURITY ANALYSIS REPORT")
    print("=" * 60)

    print("\n[Basic Headers]")
    print(f"From: {headers['From']}")
    print(f"Reply-To: {headers['Reply-To']}")
    print(f"To: {headers['To']}")
    print(f"Subject: {headers['Subject']}")
    print(f"Date: {headers['Date']}")
    print(f"Message-ID: {headers['Message-ID']}")
    print(f"Return-Path: {headers['Return-Path']}")

    print("\n[Authentication Results]")
    print(f"SPF: {auth_results['SPF']}")
    print(f"DKIM: {auth_results['DKIM']}")
    print(f"DMARC: {auth_results['DMARC']}")

    print("\n[From vs Reply-To Check]")
    mismatch_found, mismatch_message = mismatch_result
    print(f"Mismatch Found: {'YES' if mismatch_found else 'NO'}")
    print(f"Details: {mismatch_message}")

    print("\n[Sender Domain]")
    print(f"Sender domain: {sender_domain}")

    print("\n[Domain Age]")
    age_days, age_message = domain_age
    print(f"Age in days: {age_days}")
    print(f"Details: {age_message}")

    print("\n[Lookalike Domain Check]")
    if lookalike_warnings:
        for warning in lookalike_warnings:
            print(f"WARNING: {warning}")
    else:
        print("No lookalike domain warning found.")

    print("\n[URLs Found]")
    if urls:
        for url in urls:
            print(f"- {url}")
    else:
        print("No URLs found.")

    print("\n[LLM Analysis]")
    if llm_error:
        print(llm_error)
    elif llm_result:
        print(f"Urgency/Fear Tactics: {'YES' if llm_result['urgency_or_fear_tactics'] else 'NO'}")
        print(f"Impersonation: {'YES' if llm_result['impersonation'] else 'NO'}")
        print(f"Authority Pressure: {'YES' if llm_result['authority_pressure'] else 'NO'}")
        print(f"Requests Credentials/Action: {'YES' if llm_result['requests_credentials_or_action'] else 'NO'}")
        print(f"Summary: {llm_result['summary']}")

    print("\n[VirusTotal URL Checks]")
    if not url_reports:
        print("No URLs to check.")
    else:
        for url, report in url_reports:
            status = report["status"]
            if status == "found":
                print(f"- {url}: {report['malicious']}/{report['total_engines']} engines flagged malicious")
            elif status == "not_scanned":
                print(f"- {url}: not previously scanned by VirusTotal; submitted for analysis")
            elif status == "skipped":
                print(f"- {url}: skipped (VIRUSTOTAL_API_KEY not set)")
            else:
                print(f"- {url}: error - {report['message']}")

    print("\n[Quick Risk Notes]")
    risk_notes = []

    if mismatch_found:
        risk_notes.append("From and Reply-To domains do not match.")

    if auth_results["SPF"] in ["fail", "softfail"]:
        risk_notes.append("SPF failed or softfailed.")

    if auth_results["DKIM"] in ["fail", "none", "not found"]:
        risk_notes.append("DKIM is missing or failed.")

    if auth_results["DMARC"] == "fail":
        risk_notes.append("DMARC failed.")

    if isinstance(age_days, int) and age_days < 30:
        risk_notes.append("Sender domain is very new.")

    if lookalike_warnings:
        risk_notes.append("Possible lookalike domain detected.")

    if llm_result and any(
        llm_result[flag]
        for flag in (
            "urgency_or_fear_tactics",
            "impersonation",
            "authority_pressure",
            "requests_credentials_or_action",
        )
    ):
        risk_notes.append("LLM detected social engineering tactics (see LLM Analysis).")

    if any(report.get("malicious", 0) > 0 for _, report in url_reports):
        risk_notes.append("VirusTotal flagged a malicious URL.")

    if risk_notes:
        for note in risk_notes:
            print(f"- {note}")
    else:
        print("No major basic warning found.")

    print("\n" + "=" * 60)


def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_email.py path/to/email.eml")
        sys.exit(1)

    file_path = sys.argv[1]

    msg = load_email(file_path)
    headers = get_basic_headers(msg)

    from_header = headers["From"]
    reply_to_header = headers["Reply-To"]

    sender_domain = extract_email_domain(from_header)

    mismatch_result = check_from_reply_to_mismatch(from_header, reply_to_header)

    plain_text, html_text = extract_body(msg)

    urls = []
    urls.extend(extract_urls_from_text(plain_text))
    urls.extend(extract_urls_from_text(html_text))
    urls.extend(extract_urls_from_html(html_text))

    # Remove duplicate URLs
    urls = sorted(set(urls))

    auth_results = parse_authentication_results(
        headers["Authentication-Results"],
        headers["Received-SPF"]
    )

    registered_sender_domain = get_registered_domain(sender_domain)

    domain_age = get_domain_age(registered_sender_domain) if registered_sender_domain else (
        "unknown",
        "No sender domain found."
    )

    lookalike_warnings = check_lookalike_domain(registered_sender_domain)

    llm_result, llm_error = analyze_with_llm(headers["Subject"], plain_text, html_text)

    vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    url_reports = []
    if vt_api_key:
        if len(urls) > 1:
            print(f"Checking {len(urls)} URLs against VirusTotal (free-tier rate limit, ~16s between requests)...")
        for i, url in enumerate(urls):
            if i > 0:
                time.sleep(16)
            url_reports.append((url, check_url_virustotal(url, vt_api_key)))
    else:
        url_reports = [(url, {"status": "skipped"}) for url in urls]

    print_report(
        headers=headers,
        auth_results=auth_results,
        mismatch_result=mismatch_result,
        urls=urls,
        sender_domain=registered_sender_domain,
        domain_age=domain_age,
        lookalike_warnings=lookalike_warnings,
        llm_result=llm_result,
        llm_error=llm_error,
        url_reports=url_reports
    )


if __name__ == "__main__":
    main()
