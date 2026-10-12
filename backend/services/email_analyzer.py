from backend.services.recommendation_engine import generate_recommendations
from backend.services.sender_analyzer import analyze_sender
from backend.services.content_analyzer import analyze_content
from backend.services.url_analyzer import analyze_url
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.risk_engine import calculate_phishing_score
from backend.utils.feature_engineering import extract_email_features
from ml.predict import load_model, predict_email, prepare_features
ML_MODEL = load_model()

def analyze_email(
    sender,
    subject,
    body,
    urls=None,
    attachment_name="",
    display_name=None
):
    """
    Complete email analysis pipeline.

    Flow:
    Sender → Content → URLs → Attachment
            ↓
        Risk Engine
            ↓
      Final Result
    """

    # -------------------------------------------------
    # 1. Sender Analysis
    # -------------------------------------------------

    sender_result = analyze_sender(
        sender,
        display_name
    )

    # -------------------------------------------------
    # 2. Content Analysis
    # -------------------------------------------------

    content_result = analyze_content(
        subject,
        body
    )

    # -------------------------------------------------
    # 3. URL Analysis
    # -------------------------------------------------

    if urls is None:
        urls = []

    url_results = []

    for url in urls:
        url_results.append(
            analyze_url(url)
        )

    # -------------------------------------------------
    # 4. Attachment Analysis
    # -------------------------------------------------

    attachment_result = analyze_attachment(
        attachment_name
    )

    # -------------------------------------------------
    # 5. Risk Engine
    # -------------------------------------------------

    risk_result = calculate_phishing_score(
        sender_result,
        content_result,
        url_results,
        attachment_result
    )
        # -------------------------------------------------
        # 5. ML Feature Extraction
        # -------------------------------------------------

    ml_features = extract_email_features(
        sender=sender,
        subject=subject,
        body=body,
        urls=urls,
        attachment_name=attachment_name
    )
    ml_features_df = prepare_features(
        ml_features
    )
    ml_prediction = predict_email(
    ML_MODEL,
    ml_features_df,
)

    ml_classification = ml_prediction["classification"]
    
        # -------------------------------------------------
    # 6. Security Recommendations
    # -------------------------------------------------

    recommendations = generate_recommendations(
        risk_result["risk_score"],
        risk_result["classification"],
        risk_result["reasons"]
    )

    # -------------------------------------------------
    # 7. Final Combined Result
    # -------------------------------------------------

    return {
        "email": {
            "sender": sender,
            "subject": subject,
            "urls": urls,
            "attachment_name": attachment_name,
        },
        

        "sender_analysis": sender_result,

        "content_analysis": content_result,

        "url_analysis": url_results,

        "attachment_analysis": attachment_result,

        "risk_analysis": risk_result,
             "ml_analysis": {
    "model": "RandomForestClassifier",
    "classification": ml_prediction["classification"],
    "legitimate_probability": ml_prediction["legitimate_probability"],
    "phishing_probability": ml_prediction["phishing_probability"],
    "confidence": ml_prediction["confidence"],
},

        "recommendations": recommendations,
    }