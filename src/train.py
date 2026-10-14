"""Train an educational baseline model from a user-provided labeled CSV."""
from __future__ import annotations
import argparse
from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from src.features import FEATURE_NAMES, extract_features

def main():
    parser = argparse.ArgumentParser(description='Train PhishGuard AI from a labeled CSV.')
    parser.add_argument('--input', required=True, help='CSV with url and label columns (1=phishing, 0=legitimate)')
    parser.add_argument('--output', default='models/phishing_model.joblib')
    args = parser.parse_args()
    data = pd.read_csv(args.input)
    if not {'url', 'label'}.issubset(data.columns):
        raise SystemExit("CSV must contain 'url' and 'label' columns.")
    data = data.dropna(subset=['url', 'label']).copy()
    data['label'] = pd.to_numeric(data['label'], errors='coerce')
    data = data[data['label'].isin([0, 1])]
    if data['label'].nunique() != 2 or len(data) < 20:
        raise SystemExit('Need at least 20 valid rows and both labels 0 and 1.')
    rows, labels, skipped = [], [], 0
    for url, label in zip(data['url'].astype(str), data['label'].astype(int)):
        try:
            feature = extract_features(url)
            rows.append([feature[name] for name in FEATURE_NAMES])
            labels.append(label)
        except ValueError:
            skipped += 1
    X = pd.DataFrame(rows, columns=FEATURE_NAMES)
    y = pd.Series(labels, name='label')
    if len(y) < 20 or y.nunique() != 2:
        raise SystemExit('Too few valid URLs remain after parsing.')
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    model = RandomForestClassifier(n_estimators=250, class_weight='balanced', random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    predicted = model.predict(X_test)
    print(f'Rows used: {len(y)}; skipped invalid rows: {skipped}')
    print(f'Accuracy:  {accuracy_score(y_test, predicted):.3f}')
    print(f'Precision: {precision_score(y_test, predicted, zero_division=0):.3f}')
    print(f'Recall:    {recall_score(y_test, predicted, zero_division=0):.3f}')
    print(f'F1 score:  {f1_score(y_test, predicted, zero_division=0):.3f}')
    print('Confusion matrix [[TN, FP], [FN, TP]]:')
    print(confusion_matrix(y_test, predicted, labels=[0, 1]))
    print(classification_report(y_test, predicted, target_names=['legitimate', 'phishing'], zero_division=0))
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True); joblib.dump(model, output)
    print(f'Saved model to: {output}')
    print('Metrics describe this row-level split only; domain leakage can inflate results.')

if __name__ == '__main__':
    main()
