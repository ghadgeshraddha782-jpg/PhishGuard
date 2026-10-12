import re


URGENCY_KEYWORDS = [
    "urgent",
    "immediately",
    "right now",
    "act now",
    "as soon as possible",
    "within 24 hours",
    "final notice",
    "last warning",
]

CREDENTIAL_KEYWORDS = [
    "password",
    "username",
    "login",
    "verify your account",
    "verification",
    "credentials",
    "sign in",
]

FINANCIAL_KEYWORDS = [
    "payment",
    "invoice",
    "bank",
    "credit card",
    "debit card",
    "refund",
    "transaction",
    "money",
]

THREAT_KEYWORDS = [
    "suspended",
    "blocked",
    "closed",
    "terminated",
    "penalty",
    "legal action",
    "reported",
]

REWARD_KEYWORDS = [
    "winner",
    "won",
    "prize",
    "reward",
    "gift",
    "congratulations",
]

PERSONAL_INFO_KEYWORDS = [
    "date of birth",
    "phone number",
    "address",
    "personal information",
    "identity",
    "id proof",
]
OPPORTUNITY_KEYWORDS = [
    "congratulations",
    "shortlisted",
    "selected",
    "selection",
    "internship",
    "stipend",
    "offer",
    "benefits",
    "placement assistance",
]

ACTION_KEYWORDS = [
    "action required",
    "register now",
    "registration",
    "application form",
    "complete registration",
    "apply now",
    "deadline",
    "before",
]

REWARD_KEYWORDS = [
    "prize",
    "reward",
    "certificate",
    "bonus",
    "cash",
    "up to ₹",
]


def count_matches(text, keywords):
    """Count matching security keywords."""

    count = 0
    matched = []

    text = text.lower()

    for keyword in keywords:
        if keyword.lower() in text:
            count += 1
            matched.append(keyword)

    return count, matched


def analyze_content(subject, body):
    """
    Analyze subject and body for phishing-related
    social engineering indicators.
    """

    subject = subject or ""
    body = body or ""

    combined_text = f"{subject} {body}".strip()

    findings = []

    urgency_count, urgency_matches = count_matches(
        combined_text,
        URGENCY_KEYWORDS
    )

    credential_count, credential_matches = count_matches(
        combined_text,
        CREDENTIAL_KEYWORDS
    )

    financial_count, financial_matches = count_matches(
        combined_text,
        FINANCIAL_KEYWORDS
    )

    threat_count, threat_matches = count_matches(
        combined_text,
        THREAT_KEYWORDS
    )

    reward_count, reward_matches = count_matches(
        combined_text,
        REWARD_KEYWORDS
    )
    opportunity_count, opportunity_matches = count_matches(
    combined_text,
    OPPORTUNITY_KEYWORDS
)

    action_count, action_matches = count_matches(
    combined_text,
    ACTION_KEYWORDS
)

    personal_count, personal_matches = count_matches(
        combined_text,
        PERSONAL_INFO_KEYWORDS
    )

    # -------------------------------------------------
    # Urgency
    # -------------------------------------------------

    if urgency_count > 0:
        findings.append({
            "indicator": "Urgency",
            "count": urgency_count,
            "matches": urgency_matches,
            "explanation": (
                "The message uses urgent language that may pressure "
                "the recipient into acting quickly."
            )
        })

    # -------------------------------------------------
    # Credential request
    # -------------------------------------------------

    if credential_count > 0:
        findings.append({
            "indicator": "Credential Request",
            "count": credential_count,
            "matches": credential_matches,
            "explanation": (
                "The message contains language related to passwords, "
                "login credentials, or account verification."
            )
        })

    # -------------------------------------------------
    # Financial pressure
    # -------------------------------------------------

    if financial_count > 0:
        findings.append({
            "indicator": "Financial Pressure",
            "count": financial_count,
            "matches": financial_matches,
            "explanation": (
                "The message contains payment or financial-related "
                "language."
            )
        })

    # -------------------------------------------------
    # Threat / fear
    # -------------------------------------------------

    if threat_count > 0:
        findings.append({
            "indicator": "Threat / Fear",
            "count": threat_count,
            "matches": threat_matches,
            "explanation": (
                "The message may use threats, account suspension, "
                "or negative consequences to pressure the recipient."
            )
        })

    # -------------------------------------------------
    # Reward / prize
    # -------------------------------------------------

    if reward_count > 0:
        findings.append({
            "indicator": "Reward / Prize",
            "count": reward_count,
            "matches": reward_matches,
            "explanation": (
                "The message contains reward or prize-related "
                "language that may be used as a social engineering lure."
            )
        })
        # -------------------------------------------------
# Opportunity / Internship lure
# -------------------------------------------------

    if opportunity_count > 0:
        findings.append({
        "indicator": "Opportunity / Internship Lure",
        "count": opportunity_count,
        "matches": opportunity_matches,
        "explanation": (
            "The message contains opportunity, selection, "
            "internship, stipend, or benefit-related language "
            "that may be used as a social engineering lure."
        )
    })

# -------------------------------------------------
# Action / Registration pressure
# -------------------------------------------------

    if action_count > 0:
        findings.append({
        "indicator": "Action / Registration Pressure",
        "count": action_count,
        "matches": action_matches,
        "explanation": (
            "The message asks the recipient to register, "
            "complete an application, or act before a deadline."
        )
    })

    # -------------------------------------------------
    # Personal information
    # -------------------------------------------------

    if personal_count > 0:
        findings.append({
            "indicator": "Personal Information Request",
            "count": personal_count,
            "matches": personal_matches,
            "explanation": (
                "The message appears to request personal or identity "
                "information."
            )
        })

    # -------------------------------------------------
    # Generic greeting
    # -------------------------------------------------

    generic_greetings = [
        "dear customer",
        "dear user",
        "dear member",
        "dear valued customer",
        "hello user",
    ]

    generic_greeting_found = any(
        greeting in combined_text.lower()
        for greeting in generic_greetings
    )

    if generic_greeting_found:
        findings.append({
            "indicator": "Generic Greeting",
            "count": 1,
            "matches": ["generic greeting"],
            "explanation": (
                "The message uses a generic greeting instead of "
                "addressing the recipient specifically."
            )
        })

    # -------------------------------------------------
    # Exclamation marks
    # -------------------------------------------------

    exclamation_count = combined_text.count("!")

    # -------------------------------------------------
    # Uppercase ratio
    # -------------------------------------------------

    letters = [
        char for char in combined_text
        if char.isalpha()
    ]

    uppercase_ratio = 0.0

    if letters:
        uppercase_ratio = (
            sum(char.isupper() for char in letters)
            / len(letters)
        )

    return {
        "urgency_keyword_count": urgency_count,
        "credential_keyword_count": credential_count,
        "financial_keyword_count": financial_count,
        "threat_keyword_count": threat_count,
        "reward_keyword_count": reward_count,
        "opportunity_keyword_count": opportunity_count,
        "action_keyword_count": action_count,
        "personal_info_keyword_count": personal_count,
        "generic_greeting": generic_greeting_found,
        "exclamation_count": exclamation_count,
        "uppercase_ratio": round(uppercase_ratio, 3),
        "content_findings": findings,
    }