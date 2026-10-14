# Model evaluation methodology

## Status
**Training run:** [GitHub Actions run #1](https://github.com/abhinavprasadsingh/PhishShield/actions/runs/38618944295) completed successfully on 2026-10-14. It prepared 235,370 unique URLs; 235,352 rows were used after feature parsing and 18 invalid rows were skipped. The 80/20 test split used approximate domain grouping (188,224 train rows; 47,128 test rows). The trained model and full logs are in the [Actions artifact](https://github.com/abhinavprasadsingh/PhishShield/actions/runs/38618944295/artifacts/11921235635), available until 2026-11-13. The artifact/model is not committed to the repository and is not automatically deployed to the public Streamlit app.

### Held-out test results

| Model | Accuracy | Precision | Recall | F1 | Average precision (PR-AUC) |
|---|---:|---:|---:|---:|---:|
| HistGradientBoosting | 0.997 | 0.999 | 0.994 | 0.996 | 0.999 |
| Random Forest | 0.997 | 0.998 | 0.994 | 0.996 | 0.998 |
| Logistic Regression | 0.995 | 0.999 | 0.989 | 0.994 | 0.998 |

The selected model was HistGradientBoosting (selected by held-out F1). Its confusion matrix, in `[[TN, FP], [FN, TP]]` order, was `[[26759, 19], [125, 20225]]`. These are results on this dataset and this split, not proof of equivalent real-world performance.
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
These metrics are model-selection estimates because the test set was used to select the winning model; a separate untouched benchmark is needed for a final performance claim. Domain grouping is approximate and can fail to separate related registrable domains correctly. The unusually high scores should be independently checked for dataset artifacts, duplicates, label leakage, and distribution mismatch before making strong public claims. One dataset cannot guarantee future phishing detection.