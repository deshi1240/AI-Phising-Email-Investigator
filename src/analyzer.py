import re
from email.utils import parseaddr
from pathlib import Path

import joblib

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = BASE_DIR / "models" / "phishing_model.pkl"

ml_model = joblib.load(MODEL_PATH)


# AI Phishing Email Investigator
# Phase 1: Rule-based phishing detection


SUSPICIOUS_PHRASES = {
    "urgent": 10,
    "immediately": 10,
    "verify your account": 20,
    "verify your password": 25,
    "account suspended": 20,
    "click here": 15,
    "click the link": 15,
    "confirm your identity": 20,
    "update your payment": 20,
    "you have won": 20,
    "claim your prize": 20,
}

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".link",
    ".info",
    ".buzz"
}

KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "chase": "chase.com"
}

def normalize_domain(domain):

    replacements = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t"
    }

    normalized = domain.lower()

    for number, letter in replacements.items():
        normalized = normalized.replace(number, letter)

    return normalized

def analyze_sender(sender):

    sender_score = 0
    sender_indicators = []

    display_name, email_address = parseaddr(sender)

    if "@" not in email_address:
        sender_indicators.append(
            "Unable to extract a valid sender email address"
        )
        return sender_score, sender_indicators

    domain = email_address.split("@")[-1].lower()

    normalized_domain = normalize_domain(domain)

    for brand, official_domain in KNOWN_BRANDS.items():

        official_sender = (
            domain == official_domain
            or domain.endswith("." + official_domain)
        )

        if brand in normalized_domain and not official_sender:

            sender_score += 30

            sender_indicators.append(
                f"Possible {brand.title()} impersonation detected: "
                f"{domain} (+30)"
            )

    return sender_score, sender_indicators

def extract_urls(email_text):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, email_text)

def analyze_urls(email_text):

    url_score = 0
    url_indicators = []

    urls = extract_urls(email_text)

    for url in urls:

        if url.startswith("http://"):
            url_score += 15
            url_indicators.append(
                f"Insecure HTTP link detected: {url} (+15)"
            )

        for tld in SUSPICIOUS_TLDS:

            if tld in url.lower():
                url_score += 20
                url_indicators.append(
                    f"Suspicious domain ending detected: {tld} (+20)"
                )

    return url_score, url_indicators

def analyze_with_ml(email_text):

    probabilities = ml_model.predict_proba([email_text])[0]

    classes = ml_model.classes_

    phishing_index = list(classes).index("phishing")

    phishing_probability = probabilities[phishing_index]

    prediction = ml_model.predict([email_text])[0]

    return prediction, phishing_probability


def analyze_email(sender, email_text):

    risk_score = 0
    indicators = []

    processed_text = email_text.lower()

    for phrase, points in SUSPICIOUS_PHRASES.items():

        if phrase in processed_text:

            risk_score += points

            indicators.append(
                f"Suspicious phrase detected: '{phrase}' (+{points})"
            )

    url_score, url_indicators = analyze_urls(email_text)

    risk_score += url_score

    indicators.extend(url_indicators)

    sender_score, sender_indicators = analyze_sender(sender)

    risk_score += sender_score
    indicators.extend(sender_indicators)

    prediction, phishing_probability = analyze_with_ml(email_text)

    if prediction == "phishing":

        if phishing_probability >= 0.80:
            ml_points = 25

        elif phishing_probability >= 0.60:
            ml_points = 15

        else:
            ml_points = 10

        risk_score += ml_points

        indicators.append(
            f"ML model classified email as phishing "
            f"({phishing_probability:.1%} confidence) "
            f"(+{ml_points})"
        )

    risk_score = min(risk_score, 100)

    return risk_score, indicators


def get_risk_level(score):

    if score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    else:
        return "LOW"


def read_email():

    print("\nPaste the email body below.")
    print("Type END on a new line when finished.\n")

    lines = []

    while True:

        line = input()

        if line.strip().upper() == "END":
            break

        lines.append(line)

    return "\n".join(lines)

def main():

    print("\n================================")
    print(" AI PHISHING EMAIL INVESTIGATOR")
    print("================================")

    sender = input("\nSender: ").strip()

    email_text = read_email()

    if not email_text.strip():

        print("\nNo email content was provided.")
        return

    print("\nAnalyzing email...")

    score, indicators = analyze_email(
        sender,
        email_text
    )

    risk_level = get_risk_level(score)

    print("\n================================")
    print(" ANALYSIS RESULTS")
    print("================================")

    print(f"\nSender: {sender}")

    print(f"Risk Score: {score}/100")
    print(f"Risk Level: {risk_level}")

    print("\nIndicators Found:")

    if indicators:

        for indicator in indicators:
            print(f"[+] {indicator}")

    else:

        print("[-] No suspicious indicators detected.")


if __name__ == "__main__":
    main()