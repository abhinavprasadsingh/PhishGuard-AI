# PhishShield — Intelligent Phishing Detection 🛡️

PhishShield is a web application that analyzes URLs for potential phishing indicators and presents clear, explainable risk signals. It helps users assess suspicious links by examining URL structure and hostname patterns, with support for a supervised machine-learning workflow to classify URLs as **potential phishing** or **likely legitimate**.

> **Current project status:** The web app currently supports explainable heuristic demo mode. The repository does not yet include a trained model or a bundled labeled dataset. Supervised ML results and evaluation metrics must only be reported after a dataset is sourced, the model is trained, and evaluation is completed.

## Why this matters

Fake banking links, delivery notifications, login pages, and fraudulent offers can be designed to steal credentials. PhishShield helps users inspect suspicious URL patterns before deciding what to do next. It is an educational aid, not a replacement for browser protection or security review.

## Features

- Premium dark Streamlit interface
- URL parsing and feature extraction without visiting the submitted URL
- Explainable heuristic demo mode when no trained model is available
- Optional scikit-learn model loaded from `models/phishing_model.joblib`
- Shows extracted features and human-readable warning signals
- Training pipeline compares Logistic Regression, Random Forest, and HistGradientBoosting
- Evaluation reporting for accuracy, precision, recall, F1, average precision (PR-AUC), and a confusion matrix
- Automated tests and GitHub Actions checks

## Tech stack

- **Python** for application and analysis
- **Pandas** for tabular feature inputs and dataset handling
- **scikit-learn** for supervised classification and evaluation
- **Streamlit** for the interactive web demo
- **HTML/CSS** for interface styling
- **SQLite** is a possible future addition for local scan history; it is not currently required by the core app.

## Dataset plan

Use a properly sourced labeled URL dataset. [PhishTank's developer information](https://phishtank.org/developer_info.php) is one possible source for verified phishing URL data. Pair it with a separately sourced benign URL dataset, and check licensing, provenance, timestamps, class balance, duplicates, and domain overlap before training. Do not assume a source is suitable until its current terms and data format have been reviewed.

Prepare a CSV with two columns:
- `url`: URL text
- `label`: `1` for phishing, `0` for legitimate

Keep raw data out of Git (for example, `data/urls.csv`) and never open URLs from the dataset. Avoid training/test leakage by separating related domains where feasible and documenting the split.

## Run locally (Windows PowerShell)

1. Install Python 3.11 or newer from https://www.python.org/downloads/.
2. Open PowerShell in the project folder.
3. Create an environment, install dependencies, and launch Streamlit:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Streamlit prints a local address, usually http://localhost:8501.

## Deploy on Streamlit Community Cloud

1. Push this repository to GitHub.
2. Open https://share.streamlit.io/ and sign in with GitHub.
3. Create an app using repository `abhinavprasadsingh/PhishGuard-AI`, branch `main`, and main file `app.py`.
4. Deploy and test valid and invalid inputs.

A successful GitHub push does not itself confirm that the hosted app has redeployed successfully. Check the deployment status in Streamlit Community Cloud.

## Train a supervised model (optional)

Once you have a labeled CSV at `data/urls.csv`, run:

```powershell
python -m src.train --input data/urls.csv
```

The training script removes exact duplicate URLs, compares Logistic Regression, Random Forest, and HistGradientBoosting, reports evaluation metrics, and saves the selected model to `models/phishing_model.joblib`. Review [the evaluation notes](reports/evaluation.md). Metrics depend on dataset quality, label reliability, and split design; do not claim performance without running and documenting the experiment.

## Tests

```powershell
python -m compileall -q app.py src tests
pytest -q
```

GitHub Actions runs these checks on pushes and pull requests.

## Viva explanation

“The system extracts measurable features from a URL and can use a classifier trained on labeled phishing and legitimate examples to estimate its class. It also shows understandable warning signals so users can inspect why a URL deserves caution. A prediction is not a guarantee of safety.”

## Limitations and safe use

- Heuristic demo scores are **not** machine-learning predictions or calibrated probabilities.
- URL features alone can miss sophisticated phishing and can flag legitimate URLs.
- HTTPS does not prove that a website is legitimate.
- A low-risk result is not a safety guarantee.
- The app parses the submitted URL as text; it does not visit it, follow redirects, or fetch page content.
- Avoid submitting URLs that contain private access tokens, session IDs, or personal data.

## Project structure

```text
PhishGuard-AI/
├── app.py
├── requirements.txt
├── src/
│   ├── features.py
│   └── train.py
├── tests/
├── data/README.md
├── models/README.md
├── reports/evaluation.md
├── docs/VIVA.md
└── .github/workflows/tests.yml
```

## License

MIT. See [LICENSE](LICENSE).
