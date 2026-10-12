def generate_recommendations(risk_score, classification, reasons):
    """
    Generate defensive security recommendations
    based on the detected phishing indicators.
    """

    recommendations = []

    # -------------------------------------------------
    # Basic recommendation based on risk
    # -------------------------------------------------

    if risk_score >= 41:
        recommendations.append(
            "Do not click links in this email until the sender "
            "and destination are independently verified."
        )

        recommendations.append(
            "Do not open unexpected attachments."
        )

        recommendations.append(
            "Verify the request through a trusted channel "
            "such as the official website, application, or known contact."
        )

        recommendations.append(
            "Report the email to the appropriate security or "
            "IT team if it appears suspicious."
        )

    elif risk_score >= 21:
        recommendations.append(
            "Treat this email with caution and verify the request "
            "before taking any action."
        )

        recommendations.append(
            "Independently verify the sender, organization, and "
            "opportunity using official sources."
        )

    else:
        recommendations.append(
            "No major phishing indicators were detected, but "
            "continue following normal email security practices."
        )

    # -------------------------------------------------
    # Indicator-specific recommendations
    # -------------------------------------------------

    indicators = [
        reason.get("indicator", "").lower()
        for reason in reasons
    ]

    if "suspicious url" in indicators:
        recommendations.append(
            "Avoid using links from the email. Navigate directly "
            "to the official website or application instead."
        )

    if "credential request" in indicators:
        recommendations.append(
            "Never provide passwords or other credentials through "
            "an unexpected email request."
        )

    if "suspicious attachment" in indicators:
        recommendations.append(
            "Do not execute or open the suspicious attachment."
        )

    if "financial pressure" in indicators:
        recommendations.append(
            "Verify payment or financial requests using an "
            "independent trusted contact."
        )

    if "opportunity / internship lure" in indicators:
        recommendations.append(
            "Independently verify the internship, job, or opportunity "
            "through the organization's official website or known "
            "recruitment channel before registering."
        )

    if "action / registration pressure" in indicators:
        recommendations.append(
            "Do not rush to complete a registration or application "
            "because of a deadline. Verify the request first."
        )

    if "reward / prize" in indicators:
        recommendations.append(
            "Be cautious of certificates, prizes, stipends, or other "
            "benefits used to encourage immediate action."
        )

    return recommendations