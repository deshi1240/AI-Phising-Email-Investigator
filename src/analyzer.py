import re
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


def analyze_email(email_text):

    risk_score = 0
    indicators = []

    email_text = email_text.lower()

    for phrase, points in SUSPICIOUS_PHRASES.items():

        if phrase in email_text:

            risk_score += points

            indicators.append(
                f"Suspicious phrase detected: '{phrase}' (+{points})"
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


sample_email = """
URGENT!

Your account has been suspended.

Click the link below immediately to verify your password.
"""


score, indicators = analyze_email(sample_email)

risk_level = get_risk_level(score)


print("\n==============================")
print(" AI PHISHING EMAIL INVESTIGATOR")
print("==============================")

print(f"\nRisk Score: {score}/100")
print(f"Risk Level: {risk_level}")

print("\nIndicators Found:")

for indicator in indicators:
    print(f"[+] {indicator}")