# Model evaluation notes

PhishGuard's training command compares Logistic Regression, Random Forest, and HistGradientBoosting on a held-out set. The positive class is phishing (label 1). It reports accuracy, precision, recall, F1, average precision (PR-AUC), and a confusion matrix.

## Important evaluation caveats

- Remove exact duplicate URLs before splitting; the training script does this.
- It attempts an approximate grouping split by the final two hostname labels to reduce domain leakage. This is **not** a full Public Suffix List implementation and may group some domains incorrectly (for example, domains under multi-part public suffixes). Treat it as a basic safeguard, not a rigorous benchmark.
- If there are too few distinct groups, the script falls back to a stratified row split and prints that fact.
- Use an independently sourced, domain-separated test set for stronger claims.
- Do not report a score from a single split as proof of production performance.
- Never open URLs from a dataset during preprocessing or evaluation.

## Dataset expectations

Provide a CSV with columns:

- `url`: URL string
- `label`: `1` for phishing, `0` for legitimate

Verify the source, license, label meaning, collection date, class balance, and any duplicates before training. Keep datasets and generated model artifacts out of Git unless their licenses and repository size make inclusion appropriate.
