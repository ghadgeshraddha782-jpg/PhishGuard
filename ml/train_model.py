import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier


DATASET_FILE = "data/phishing_email_features.csv"


def load_dataset():
    """
    Load the engineered feature dataset.
    """

    df = pd.read_csv(DATASET_FILE)

    return df


def split_dataset(df):
    """
    Split the dataset into:
    70% training
    15% validation
    15% testing
    """

    # -------------------------------------------------
    # Separate features and target
    # -------------------------------------------------

    feature_columns = [
        column
        for column in df.columns
        if column not in ["email_id", "label"]
    ]

    X = df[feature_columns]
    y = df["label"]

    # -------------------------------------------------
    # First split:
    # 70% train
    # 30% temporary
    # -------------------------------------------------

    X_train, X_temp, y_train, y_temp = train_test_split(
        X,
        y,
        test_size=0.30,
        random_state=42,
        stratify=y,
    )

    # -------------------------------------------------
    # Second split:
    # 15% validation
    # 15% test
    # -------------------------------------------------

    X_validation, X_test, y_validation, y_test = (
        train_test_split(
            X_temp,
            y_temp,
            test_size=0.50,
            random_state=42,
            stratify=y_temp,
        )
    )

    return (
        X_train,
        X_validation,
        X_test,
        y_train,
        y_validation,
        y_test,
    )
def create_logistic_regression_model():
    """
    Create the baseline Logistic Regression model.
    """

    model = LogisticRegression(
        max_iter=1000,
        random_state=42,
    )
    return model
def create_random_forest_model():
    """
    Create the Random Forest classification model.
    """

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
    )

    return model
def train_model(model, X_train, y_train):
    """
    Train the Logistic Regression model
    using the training dataset.
    """

    model.fit(X_train, y_train)

    return model
def train_random_forest(model, X_train, y_train):
    """
    Train the Random Forest model
    using the training dataset.
    """

    model.fit(X_train, y_train)

    return model
def validate_model(model, X_validation, y_validation):
    """
    Generate predictions on the validation dataset.
    """

    predictions = model.predict(X_validation)

    return predictions
def test_model(model, X_test):
    """
    Generate predictions on the unseen test dataset.
    """

    predictions = model.predict(X_test)

    return predictions
def predict_random_forest(model, X):
    """
    Generate predictions using the Random Forest model.
    """

    predictions = model.predict(X)

    return predictions
def calculate_accuracy(y_actual, predictions):
    """
    Calculate validation accuracy.
    """

    correct_predictions = (y_actual == predictions).sum()

    accuracy = correct_predictions / len(y_actual)

    return accuracy
def calculate_precision(y_actual, predictions):
    """
    Calculate precision for the phishing class.
    """

    from sklearn.metrics import precision_score

    precision = precision_score(
        y_actual,
        predictions,
        pos_label="PHISHING",
    )

    return precision
def calculate_recall(y_actual, predictions):
    """
    Calculate recall for the phishing class.
    """

    from sklearn.metrics import recall_score

    recall = recall_score(
        y_actual,
        predictions,
        pos_label="PHISHING",
    )

    return recall
def calculate_f1_score(y_actual, predictions):
    """
    Calculate F1-score for the phishing class.
    """

    from sklearn.metrics import f1_score

    f1 = f1_score(
        y_actual,
        predictions,
        pos_label="PHISHING",
    )

    return f1
def create_confusion_matrix(y_actual, predictions):
    """
    Create a confusion matrix for the phishing classifier.
    """

    from sklearn.metrics import confusion_matrix

    matrix = confusion_matrix(
        y_actual,
        predictions,
        labels=["LEGITIMATE", "PHISHING"],
    )

    return matrix

    


if __name__ == "__main__":

    df = load_dataset()

    (
        X_train,
        X_validation,
        X_test,
        y_train,
        y_validation,
        y_test,
    ) = split_dataset(df)
    model = create_logistic_regression_model()

    model = train_model(model, X_train, y_train)
    validation_predictions = validate_model(
    model,
    X_validation,
    y_validation,
)
    validation_accuracy = calculate_accuracy(
    y_validation,
    validation_predictions,
)
    print("Validation Accuracy:", validation_accuracy)
    validation_precision = calculate_precision(
    y_validation,
    validation_predictions,
)

    print("Validation Precision:", validation_precision)
    validation_recall = calculate_recall(
    y_validation,
    validation_predictions,
)

    print("Validation Recall:", validation_recall)
    validation_f1 = calculate_f1_score(
    y_validation,
    validation_predictions,
)

    print("Validation F1-Score:", validation_f1)
    validation_confusion_matrix = create_confusion_matrix(
    y_validation,
    validation_predictions,
)

    print("\nValidation Confusion Matrix:")
    print(validation_confusion_matrix)
    test_predictions = test_model(
    model,
    X_test,
)
    test_accuracy = calculate_accuracy(
    y_test,
    test_predictions,
)

    print("Test Accuracy:", test_accuracy)
    test_precision = calculate_precision(
    y_test,
    test_predictions,
)

    print("Test Precision:", test_precision)
    test_recall = calculate_recall(
    y_test,
    test_predictions,
)

    print("Test Recall:", test_recall)
    test_f1 = calculate_f1_score(
    y_test,
    test_predictions,
)

    print("Test F1-Score:", test_f1)
    test_confusion_matrix = create_confusion_matrix(
    y_test,
    test_predictions,
)

    print("\nTest Confusion Matrix:")
    print(test_confusion_matrix)
    random_forest_model = create_random_forest_model()

    random_forest_model = train_random_forest(
    random_forest_model,
    X_train,
    y_train,
)
    # Save the trained Random Forest model
    joblib.dump(
    random_forest_model,
    "models/random_forest_model.pkl",
)

    print("\nRandom Forest model saved successfully.")
    random_forest_validation_predictions = predict_random_forest(
    random_forest_model,
    X_validation,
)
    random_forest_test_predictions = predict_random_forest(
    random_forest_model,
    X_test,
)
    random_forest_test_accuracy = calculate_accuracy(
    y_test,
    random_forest_test_predictions,
)

    print(
    "Random Forest Test Accuracy:",
    random_forest_test_accuracy,
)
    random_forest_test_precision = calculate_precision(
    y_test,
    random_forest_test_predictions,
)

    print(
    "Random Forest Test Precision:",
    random_forest_test_precision,
)
    random_forest_test_recall = calculate_recall(
    y_test,
    random_forest_test_predictions,
)

    print(
    "Random Forest Test Recall:",
    random_forest_test_recall,
)
    random_forest_test_f1 = calculate_f1_score(
    y_test,
    random_forest_test_predictions,
)

    print(
    "Random Forest Test F1-Score:",
    random_forest_test_f1,
)
    random_forest_validation_accuracy = calculate_accuracy(
    y_validation,
    random_forest_validation_predictions,
)

    print("Random Forest Validation Accuracy:", random_forest_validation_accuracy)
    random_forest_validation_precision = calculate_precision(
    y_validation,
    random_forest_validation_predictions,
)
    print("Random Forest Validation Precision:", random_forest_validation_precision)
    random_forest_validation_recall = calculate_recall(
    y_validation,
    random_forest_validation_predictions,
)
    print("Random Forest Validation Recall:", random_forest_validation_recall)
    random_forest_validation_f1 = calculate_f1_score(
    y_validation,
    random_forest_validation_predictions,
)
    print("Random Forest Validation F1-Score:", random_forest_validation_f1)

    print("=" * 60)
    print("DATASET SPLIT")
    print("=" * 60)

    print("Total records     :", len(df))
    print("Training records  :", len(X_train))
    print("Validation records:", len(X_validation))
    print("Testing records   :", len(X_test))

    print("\nTraining labels:")
    print(y_train.value_counts())

    print("\nValidation labels:")
    print(y_validation.value_counts())

    print("\nTesting labels:")
    print(y_test.value_counts())