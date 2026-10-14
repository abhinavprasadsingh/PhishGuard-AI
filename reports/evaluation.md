# Model evaluation methodology

## Status
No measured metrics are committed yet. The supervised workflow downloads UCI PhiUSIIL dataset 967, exports URL text and labels, evaluates this project's URL-only features, and uploads model and run output as an Actions artifact. Dataset and model are not committed.
## Dataset provenance
- Dataset: PhiUSIIL Phishing URL (Website), UCI dataset 967.
- Citation: Prasad, A. & Chandra, S. (2024), Computers & Security.
- DOI: https://doi.org/10.1016/j.cose.2023.103545
- Source: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- UCI lists CC BY 4.0; retain attribution and verify current terms before redistribution.
- UCI labels are mapped to project convention: 0=legitimate, 1=phishing. Only URL text features are used; webpage-derived columns are excluded.
## Reproduce on Windows
```powershell
pip install -r requirements.txt
pip install ucimlrepo
python scripts/prepare_uci_dataset.py
python -m src.train --input data/urls.csv --output models/phishing_model.joblib
```
## Interpretation
The script compares Logistic Regression, Random Forest, and HistGradientBoosting and reports accuracy, precision, recall, F1, average precision (PR-AUC), confusion matrix, and per-class metrics. Model selection uses held-out F1, so these metrics are model-selection estimates, not a final untouched benchmark. Domain grouping is approximate; stronger evaluation should use time-based splits and registrable-domain grouping.
Do not invent metrics. Use output from a successful run and document row counts, split method, and exact metrics. One dataset cannot guarantee future phishing detection.