from core.indicators import (
    URGENT_WORDS,
    CREDENTIAL_WORDS,
    GENERIC_GREETINGS,
    SUSPICIOUS_DOMAINS
)
from core.scorer import calculate_score, get_verdict


def analyze_email(sender, subject, body):
    text = f"{subject} {body}".lower()
    flags = []

    # Urgency
    if any(word in text for word in URGENT_WORDS):
        flags.append("urgent language")

    # Credential harvesting
    if any(word in text for word in CREDENTIAL_WORDS):
        flags.append("credential request")

    # Generic greeting
    if any(greet in text for greet in GENERIC_GREETINGS):
        flags.append("generic greeting")

    # Suspicious sender
    if any(domain in sender for domain in SUSPICIOUS_DOMAINS):
        flags.append("suspicious sender")

    score = calculate_score(flags)
    verdict = get_verdict(score)

    recommendation = (
        "Do not click any links. Verify the sender independently."
        if score >= 50
        else "Exercise caution and verify the email."
    )

    return {
        "score": score,
        "verdict": verdict,
        "flags": flags,
        "recommendation": recommendation,
    }