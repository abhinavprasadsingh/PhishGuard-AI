"""Reproducible baseline comparison for labeled phishing URL data."""
from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, average_precision_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.features import FEATURE_NAMES, extract_features


def build_dataset(path: str) -> tuple[pd.DataFrame, pd.Series, list[str], int]:
    data = pd.read_csv(path)
    if not {"url", "label"}.issubset(data.columns):
        raise SystemExit("CSV must contain 'url' and 'label' columns (1=phishing, 0=legitimate).")
    data = data.dropna(subset=["url", "label"]).copy()
    data["url"] = data["url"].astype(str).str.strip()
    data["label"] = pd.to_numeric(data["label"], errors="coerce")
    data = data[data["label"].isin([0, 1])]
    data = data[data["url"] != ""].drop_duplicates(subset=["url"])
    if len(data) < 50 or data["label"].nunique() != 2:
        raise SystemExit("Need at least 50 unique valid rows and both labels 0 and 1.")

    rows, labels, urls, skipped = [], [], [], 0
    for url, label in zip(data["url"], data["label"].astype(int)):
        try:
            features = extract_features(url)
            rows.append([features[name] for name in FEATURE_NAMES])
            labels.append(label)
            urls.append(url)
        except ValueError:
            skipped += 1
    X = pd.DataFrame(rows, columns=FEATURE_NAMES)
    y = pd.Series(labels, name="label", dtype=int)
    if len(y) < 50 or y.nunique() != 2:
        raise SystemExit("Too few valid URLs remain after parsing.")
    return X, y, urls, skipped


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare baseline phishing URL classifiers.")
    parser.add_argument("--input", required=True, help="CSV containing url,label (1=phishing, 0=legitimate)")
    parser.add_argument("--output", default="models/phishing_model.joblib", help="Path for best model artifact")
    parser.add_argument("--test-size", type=float, default=0.2)
    args = parser.parse_args()
    if not 0.1 <= args.test_size <= 0.4:
        raise SystemExit("--test-size must be between 0.1 and 0.4.")

    X, y, urls, skipped = build_dataset(args.input)
    # Conservative grouping approximation for leakage reduction. For production-grade
    # evaluation, use a Public Suffix List to derive registrable domains.
    groups = [".".join((pd.Series(u).iloc[0].lower().split("://")[-1].split("/")[0].split(":")[0].split(".")[-2:])) for u in urls]
    unique_groups = len(set(groups))
    if unique_groups >= 10:
        from sklearn.model_selection import GroupShuffleSplit
        splitter = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=42)
        train_idx, test_idx = next(splitter.split(X, y, groups=groups))
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
        split_note = "approximate domain-group split"
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=args.test_size, random_state=42, stratify=y
        )
        split_note = "stratified row split (too few distinct domain groups for grouping)"
    if y_train.nunique() < 2 or y_test.nunique() < 2:
        raise SystemExit("Train/test split contains only one class. Add more data from distinct domains.")

    candidates = {
        "Logistic Regression": Pipeline([
            ("scale", StandardScaler()),
            ("model", LogisticRegression(class_weight="balanced", max_iter=2000, random_state=42)),
        ]),
        "Random Forest": RandomForestClassifier(
            n_estimators=300, class_weight="balanced", random_state=42, n_jobs=-1
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=150, learning_rate=0.1, random_state=42
        ),
    }
    results = []
    fitted = {}
    for name, model in candidates.items():
        model.fit(X_train, y_train)
        predicted = model.predict(X_test)
        try:
            positive_idx = list(model.classes_).index(1)
            probability = model.predict_proba(X_test)[:, positive_idx]
            pr_auc = average_precision_score(y_test, probability)
        except (AttributeError, ValueError):
            pr_auc = float("nan")
        metrics = {
            "model": name,
            "accuracy": accuracy_score(y_test, predicted),
            "precision": precision_score(y_test, predicted, zero_division=0),
            "recall": recall_score(y_test, predicted, zero_division=0),
            "f1": f1_score(y_test, predicted, zero_division=0),
            "pr_auc": pr_auc,
        }
        results.append(metrics)
        fitted[name] = model

    results_frame = pd.DataFrame(results).sort_values(["f1", "pr_auc"], ascending=False)
    print(f"Rows used: {len(y)} | invalid rows skipped: {skipped} | train: {len(y_train)} | test: {len(y_test)}")
    print(f"Evaluation split: {split_note}")
    print("Positive class: phishing (label=1)")
    print(results_frame.to_string(index=False, float_format=lambda value: f"{value:.3f}"))
    winner_name = str(results_frame.iloc[0]["model"])
    winner = fitted[winner_name]
    prediction = winner.predict(X_test)
    print(f"\nSelected by held-out F1: {winner_name}")
    print("Confusion matrix [[TN, FP], [FN, TP]]:")
    print(confusion_matrix(y_test, prediction, labels=[0, 1]))
    print(classification_report(y_test, prediction, labels=[0, 1], target_names=["legitimate", "phishing"], zero_division=0))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(winner, output)
    print(f"Saved selected model to: {output}")
    print("Caution: results depend on dataset quality and split design; this is not a guarantee of real-world detection.")


if __name__ == "__main__":
    main()
