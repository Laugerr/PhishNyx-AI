def calculate_score(flags):
    score = 0

    weights = {
        "urgent language": 15,
        "credential request": 25,
        "generic greeting": 10,
        "suspicious sender": 20,
    }

    for flag in flags:
        score += weights.get(flag, 5)

    return min(score, 100)


def get_verdict(score):
    if score < 25:
        return "Low Risk"
    elif score < 50:
        return "Suspicious"
    else:
        return "Likely Phishing"