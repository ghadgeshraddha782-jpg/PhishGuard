import pandas as pd

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

    # -------------------------------------------------
    # Load and split dataset
    # -------------------------------------------------

    df = load_dataset()

    (
        X_train,
        X_validation,
        X_test,
        y_train,
        y_validation,
        y_test,
    ) = split_dataset(df)

    # -------------------------------------------------
    # Dataset information
    # -------------------------------------------------

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

    # =================================================
    # LOGISTIC REGRESSION
    # =================================================

    print("\n" + "=" * 60)
    print("LOGISTIC REGRESSION")
    print("=" * 60)

    logistic_model = create_logistic_regression_model()

    logistic_model = train_model(
        logistic_model,
        X_train,
        y_train,
    )

    # Validation predictions
    logistic_validation_predictions = validate_model(
        logistic_model,
        X_validation,
        y_validation,
    )

    # Test predictions
    logistic_test_predictions = test_model(
        logistic_model,
        X_test,
    )

    # Validation metrics
    print("\nValidation Metrics:")

    print(
        "Accuracy :",
        calculate_accuracy(
            y_validation,
            logistic_validation_predictions,
        ),
    )

    print(
        "Precision:",
        calculate_precision(
            y_validation,
            logistic_validation_predictions,
        ),
    )

    print(
        "Recall   :",
        calculate_recall(
            y_validation,
            logistic_validation_predictions,
        ),
    )

    print(
        "F1-Score :",
        calculate_f1_score(
            y_validation,
            logistic_validation_predictions,
        ),
    )

    print("\nValidation Confusion Matrix:")
    print(
        create_confusion_matrix(
            y_validation,
            logistic_validation_predictions,
        )
    )

    # Test metrics
    print("\nTest Metrics:")

    print(
        "Accuracy :",
        calculate_accuracy(
            y_test,
            logistic_test_predictions,
        ),
    )

    print(
        "Precision:",
        calculate_precision(
            y_test,
            logistic_test_predictions,
        ),
    )

    print(
        "Recall   :",
        calculate_recall(
            y_test,
            logistic_test_predictions,
        ),
    )

    print(
        "F1-Score :",
        calculate_f1_score(
            y_test,
            logistic_test_predictions,
        ),
    )

    print("\nTest Confusion Matrix:")
    print(
        create_confusion_matrix(
            y_test,
            logistic_test_predictions,
        )
    )

    # =================================================
    # RANDOM FOREST
    # =================================================

    print("\n" + "=" * 60)
    print("RANDOM FOREST")
    print("=" * 60)

    random_forest_model = create_random_forest_model()

    random_forest_model = train_random_forest(
        random_forest_model,
        X_train,
        y_train,
    )

    # Validation predictions
    random_forest_validation_predictions = predict_random_forest(
        random_forest_model,
        X_validation,
    )

    # Test predictions
    random_forest_test_predictions = predict_random_forest(
        random_forest_model,
        X_test,
    )

    # Validation metrics
    print("\nValidation Metrics:")

    print(
        "Accuracy :",
        calculate_accuracy(
            y_validation,
            random_forest_validation_predictions,
        ),
    )

    print(
        "Precision:",
        calculate_precision(
            y_validation,
            random_forest_validation_predictions,
        ),
    )

    print(
        "Recall   :",
        calculate_recall(
            y_validation,
            random_forest_validation_predictions,
        ),
    )

    print(
        "F1-Score :",
        calculate_f1_score(
            y_validation,
            random_forest_validation_predictions,
        ),
    )

    print("\nValidation Confusion Matrix:")
    print(
        create_confusion_matrix(
            y_validation,
            random_forest_validation_predictions,
        )
    )

    # Test metrics
    print("\nTest Metrics:")

    print(
        "Accuracy :",
        calculate_accuracy(
            y_test,
            random_forest_test_predictions,
        ),
    )

    print(
        "Precision:",
        calculate_precision(
            y_test,
            random_forest_test_predictions,
        ),
    )

    print(
        "Recall   :",
        calculate_recall(
            y_test,
            random_forest_test_predictions,
        ),
    )

    print(
        "F1-Score :",
        calculate_f1_score(
            y_test,
            random_forest_test_predictions,
        ),
    )

    print("\nTest Confusion Matrix:")
    print(
        create_confusion_matrix(
            y_test,
            random_forest_test_predictions,
        )
    )