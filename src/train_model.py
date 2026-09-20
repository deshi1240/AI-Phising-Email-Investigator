from pathlib import Path

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# Find the project's root directory
BASE_DIR = Path(__file__).resolve().parent.parent

DATA_PATH = BASE_DIR / "data" / "emails.csv"
MODEL_PATH = BASE_DIR / "models" / "phishing_model.pkl"


# Load the dataset
data = pd.read_csv(DATA_PATH)

print(f"Loaded {len(data)} emails")

print("\nClass distribution:")
print(data["label"].value_counts())


# Separate the emails from their labels
X = data["text"]
y = data["label"]


# Divide our data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)


# Create the machine-learning pipeline
model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2)
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000
        )
    )
])


print("\nTraining model...")

model.fit(X_train, y_train)


# Test the trained model
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)


print("\n==============================")
print(" MODEL EVALUATION")
print("==============================")

print(f"\nAccuracy: {accuracy:.2%}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        zero_division=0
    )
)


# Save the trained model
joblib.dump(model, MODEL_PATH)

print(f"Model saved to: {MODEL_PATH}")