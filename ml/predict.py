import joblib
import pandas as pd


MODEL_FILE = "models/random_forest_model.pkl"
FEATURE_COLUMNS = [
    "urgent_keyword_count",
    "credential_keyword_count",
    "financial_keyword_count",
    "threat_keyword_count",
    "url_count",
    "suspicious_url_count",
    "has_ip_url",
    "has_shortened_url_pattern",
    "sender_domain_length",
    "subdomain_count",
    "suspicious_attachment",
    "generic_greeting",
    "password_request",
    "personal_info_request",
    "exclamation_count",
    "uppercase_ratio",
    "body_length",
    "subject_length",
]


def load_model():
    """
    Load the trained Random Forest model.
    """

    model = joblib.load(MODEL_FILE)

    return model
def predict_email(model, features):
    """
    Predict whether an email is legitimate or phishing
    and return class probabilities.
    """

    prediction = model.predict(features)[0]

    probabilities = model.predict_proba(features)[0]

    probability_map = dict(
        zip(
            model.classes_,
            probabilities
        )
    )

    legitimate_probability = (
        probability_map.get("LEGITIMATE", 0) * 100
    )

    phishing_probability = (
        probability_map.get("PHISHING", 0) * 100
    )

    confidence = max(
        legitimate_probability,
        phishing_probability
    )

    return {
        "classification": prediction,
        "legitimate_probability": round(
            legitimate_probability,
            2
        ),
        "phishing_probability": round(
            phishing_probability,
            2
        ),
        "confidence": round(
            confidence,
            2
        )
    }
def prepare_features(feature_dict):
    """
    Convert extracted email features into a DataFrame
    with the same column order used during training.
    """

    features_df = pd.DataFrame(
        [feature_dict],
        columns=FEATURE_COLUMNS,
    )

    return features_df
if __name__ == "__main__":

    model = load_model()
    test_features = {
    "urgent_keyword_count": 3,
    "credential_keyword_count": 2,
    "financial_keyword_count": 1,
    "threat_keyword_count": 2,
    "url_count": 1,
    "suspicious_url_count": 1,
    "has_ip_url": 0,
    "has_shortened_url_pattern": 0,
    "sender_domain_length": 18,
    "subdomain_count": 2,
    "suspicious_attachment": 0,
    "generic_greeting": 1,
    "password_request": 1,
    "personal_info_request": 1,
    "exclamation_count": 2,
    "uppercase_ratio": 0.05,
    "body_length": 250,
    "subject_length": 35,
}
    features_df = prepare_features(test_features)

    prediction = predict_email(
    model,
    features_df,
)

    print("Prediction:", prediction[0])

    print("Model loaded successfully.")
    print("Model type:", type(model).__name__)