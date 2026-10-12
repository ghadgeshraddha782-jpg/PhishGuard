import re


def analyze_sender(sender, display_name=None):
    """
    Analyze sender information using static indicators.

    Returns:
        sender_risk_score: numeric risk contribution
        sender_findings: list of explanations
    """

    risk_score = 0
    findings = []

    if not sender:
        return {
            "sender_risk_score": 15,
            "sender_findings": ["Sender address is missing."]
        }

    sender = sender.strip()

    # -------------------------------------------------
    # 1. Validate basic email format
    # -------------------------------------------------

    email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    if not re.match(email_pattern, sender):
        risk_score += 10
        findings.append("Sender email format appears unusual.")

    # -------------------------------------------------
    # 2. Extract domain
    # -------------------------------------------------

    if "@" not in sender:
        return {
            "sender_risk_score": min(risk_score + 10, 100),
            "sender_findings": findings + [
                "Sender does not contain a valid domain."
            ]
        }

    local_part, domain = sender.rsplit("@", 1)

    domain = domain.lower()

    # -------------------------------------------------
    # 3. Domain length
    # -------------------------------------------------

    if len(domain) > 40:
        risk_score += 5
        findings.append(
            "Sender domain is unusually long."
        )

    # -------------------------------------------------
    # 4. Subdomain analysis
    # -------------------------------------------------

    subdomain_count = max(domain.count(".") - 1, 0)

    if subdomain_count >= 3:
        risk_score += 5
        findings.append(
            "Sender domain contains multiple subdomains."
        )

    # -------------------------------------------------
    # 5. Unusual characters
    # -------------------------------------------------

    if "_" in domain:
        risk_score += 5
        findings.append(
            "Sender domain contains an unusual underscore character."
        )

    # -------------------------------------------------
    # 6. Suspicious domain patterns
    # -------------------------------------------------

    suspicious_terms = [
        "verify",
        "security",
        "account",
        "login",
        "update",
        "alert",
        "support"
    ]

    matched_terms = [
        term for term in suspicious_terms
        if term in domain
    ]

    if matched_terms:
        risk_score += 5
        findings.append(
            "Sender domain contains security-sensitive terms: "
            + ", ".join(matched_terms)
        )

    # -------------------------------------------------
    # 7. Display name mismatch
    # -------------------------------------------------

    if display_name:
        display_name_lower = display_name.lower()

        domain_name = domain.split(".")[0].lower()

        if (
            display_name_lower not in domain_name
            and domain_name not in display_name_lower
        ):
            risk_score += 5
            findings.append(
                "Display name and sender domain may not match."
            )

    # -------------------------------------------------
    # Final score
    # -------------------------------------------------

    risk_score = min(risk_score, 100)

    if not findings:
        findings.append(
            "No major sender-level anomalies were detected."
        )

    return {
        "sender_risk_score": risk_score,
        "sender_findings": findings
    }