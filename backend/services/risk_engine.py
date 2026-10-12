import re
def calculate_phishing_score(
    sender_result,
    content_result,
    url_results,
    attachment_result
):
    """
    Calculate the overall phishing risk score.

    Score is based on multiple independent indicators.
    Maximum score is capped at 100.
    """

    score = 0
    reasons = []

    # -------------------------------------------------
    # Sender
    # -------------------------------------------------

    sender_score = sender_result.get(
        "sender_risk_score",
        0
    )

    if sender_score > 0:
        score += 15

        reasons.append({
            "indicator": "Suspicious Sender",
            "points": 15,
            "explanation": (
                "The sender contains one or more "
                "unusual characteristics."
            )
        })

    # -------------------------------------------------
    # Content
    # -------------------------------------------------

    urgency_count = content_result.get(
        "urgency_keyword_count",
        0
    )

    credential_count = content_result.get(
        "credential_keyword_count",
        0
    )

    threat_count = content_result.get(
        "threat_keyword_count",
        0
    )
    financial_count = content_result.get(
    "financial_keyword_count",
    0
)

    personal_count = content_result.get(
    "personal_info_keyword_count",
    0
)

    generic_greeting = content_result.get(
        "generic_greeting",
        False
    )
    reward_count = content_result.get(
        "reward_keyword_count",
        0
    )

    opportunity_count = content_result.get(
        "opportunity_keyword_count",
        0
    )

    action_count = content_result.get(
        "action_keyword_count",
        0
    )

    if urgency_count > 0:
        score += 10

        reasons.append({
            "indicator": "Urgency",
            "points": 10,
            "explanation": (
                "The email uses urgent language "
                "that may pressure the recipient."
            )
        })

    if credential_count > 0:
        score += 20

        reasons.append({
            "indicator": "Credential Request",
            "points": 20,
            "explanation": (
                "The email contains language related "
                "to passwords, login credentials, "
                "or account verification."
            )
        })

    if threat_count > 0:
        score += 10

        reasons.append({
            "indicator": "Threat / Fear",
            "points": 10,
            "explanation": (
                "The email may use threats or negative "
                "consequences to pressure the recipient."
            )
        })
    if financial_count > 0:
        score += 10

        reasons.append({
        "indicator": "Financial Pressure",
        "points": 10,
        "explanation": (
            "The email contains payment, money, financial "
            "transaction, or financial pressure-related language."
        )
    })
    if personal_count > 0:
       score += 10

       reasons.append({
        "indicator": "Personal Information Request",
        "points": 10,
        "explanation": (
            "The email appears to request personal or identity "
            "information from the recipient."
        )
    })

    if generic_greeting:
        score += 5

        reasons.append({
            "indicator": "Generic Greeting",
            "points": 5,
            "explanation": (
                "The email uses a generic greeting."
            )
        })
    if opportunity_count > 0:
         score += 10

         reasons.append({
            "indicator": "Opportunity / Internship Lure",
            "points": 10,
            "explanation": (
                "The email contains opportunity, internship, "
                "selection, stipend, or benefit-related language "
                "that may be used as a social engineering lure."
            )
        })

    if action_count > 0:
        score += 10

        reasons.append({
            "indicator": "Action / Registration Pressure",
            "points": 10,
            "explanation": (
                "The email asks the recipient to register, "
                "complete an application, or act before a deadline."
            )
        })

    if reward_count > 0:
        score += 5

        reasons.append({
            "indicator": "Reward / Prize",
            "points": 5,
            "explanation": (
                "The email contains reward, certificate, "
                "stipend, or benefit-related language."
            )
        })

    # -------------------------------------------------
    # URLs
    # -------------------------------------------------

    suspicious_url_found = False

    for url_result in url_results:
        if url_result.get("url_risk_score", 0) > 0:
            suspicious_url_found = True
            break

    if suspicious_url_found:
        score += 20

        reasons.append({
            "indicator": "Suspicious URL",
            "points": 20,
            "explanation": (
                "One or more URLs contain suspicious "
                "static characteristics."
            )
        })

    # -------------------------------------------------
    # Attachment
    # -------------------------------------------------

    suspicious_attachment = attachment_result.get(
        "suspicious_attachment",
        False
    )

    if suspicious_attachment:
        score += 25

        reasons.append({
            "indicator": "Suspicious Attachment",
            "points": 25,
            "explanation": (
                "The attachment filename contains "
                "potentially risky characteristics."
            )
        })

    # -------------------------------------------------
    # Cap score
    # -------------------------------------------------

    score = min(score, 100)

    # -------------------------------------------------
    # Classification
    # -------------------------------------------------

    if score <= 20:
        classification = "LOW RISK"

    elif score <= 40:
        classification = "MODERATE RISK"

    elif score <= 70:
        classification = "SUSPICIOUS"

    else:
        classification = "HIGH RISK / LIKELY PHISHING"

    return {
        "risk_score": score,
        "classification": classification,
        "reasons": reasons,
    }