import pandas as pd

from backend.utils.feature_engineering import (
    extract_email_features
)


INPUT_FILE = "data/phishing_email_dataset.csv"
OUTPUT_FILE = "data/phishing_email_features.csv"


def generate_features():
    """
    Read the synthetic email dataset and generate
    structured security features for every email.
    """

    df = pd.read_csv(INPUT_FILE)

    feature_rows = []

    for _, row in df.iterrows():

        features = extract_email_features(
            sender=row["sender"],
            subject=row["subject"],
            body=row["body"],
            attachment_name=row["attachment_name"],
            urls=(
                [row["urls"]]
                if pd.notna(row["urls"])
                and row["urls"]
                else []
            ),
        )

        # Keep identifiers and original label
        features["email_id"] = row["email_id"]
        features["label"] = row["label"]

        feature_rows.append(features)

    feature_df = pd.DataFrame(feature_rows)

    # Put identifiers first
    identifier_columns = [
        "email_id",
        "label"
    ]

    other_columns = [
        column
        for column in feature_df.columns
        if column not in identifier_columns
    ]

    feature_df = feature_df[
        identifier_columns + other_columns
    ]

    feature_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("=" * 60)
    print("Feature Dataset Generated")
    print("=" * 60)
    print("Total records:", len(feature_df))
    print("Total features:", len(other_columns))
    print("Output:", OUTPUT_FILE)
    print("=" * 60)

    print("\nLabel distribution:")
    print(feature_df["label"].value_counts())

    print("\nFeature columns:")
    for column in other_columns:
        print("-", column)


if __name__ == "__main__":
    generate_features()