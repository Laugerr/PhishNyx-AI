def calculate_score(flags):
    score = 0

    for flag in flags:
        flag_lower = flag.lower()

        if "urgent language" in flag_lower:
            score += 15
        elif "credential" in flag_lower or "verification request" in flag_lower:
            score += 25
        elif "generic greeting" in flag_lower:
            score += 10
        elif "suspicious sender" in flag_lower or "domain pattern" in flag_lower:
            score += 20
        else:
            score += 5

    return min(score, 100)


def get_verdict(score):
    if score < 25:
        return "Low Risk"
    if score < 50:
        return "Suspicious"
    return "Likely Phishing"