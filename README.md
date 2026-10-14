# PhishGuard AI 🛡️

An educational URL-risk analysis web app built with Python, Streamlit, pandas, and scikit-learn. It explains URL patterns that may deserve caution and never opens or visits the submitted URL.

## Features

- Dark cyber-inspired Streamlit interface
- URL validation and shared feature extraction
- Explainable heuristic demo mode when no trained model is present
- Optional supervised scikit-learn model loaded from models/phishing_model.joblib
- Feature display, automated tests, and GitHub Actions checks
- Dataset and model provenance guidance

> **Important:** This is an educational tool, not a browser protection product. A low score does not prove a URL is safe. HTTPS is not proof of legitimacy. Do not enter credentials after following an unexpected link.

## Run locally (Windows PowerShell)

1. Install Python 3.11 or newer from https://www.python.org/downloads/ and ensure Python is on PATH.
2. Open PowerShell in the project folder.
3. Create and activate an environment:

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
3. Choose **Create app**, select abhinavprasadsingh/PhishGuard-AI, branch main, and main file path app.py.
4. Deploy. The platform installs packages from requirements.txt.
5. After deployment, open the generated app URL and test valid and invalid inputs.

A successful GitHub push does not itself mean the Streamlit app is deployed. Hosting account authorization and deployment status must be checked on Streamlit Community Cloud.

## Run tests

```powershell
python -m compileall -q app.py src tests
pytest -q
```

GitHub Actions runs the same checks for pushes and pull requests.

## Train a supervised model (optional)

No dataset or trained model is included. Do not invent metrics or treat the heuristic demo score as ML confidence.

Get a reputable labeled URL dataset and check its license and provenance. Prepare a CSV with columns: url (URL text) and label (1 for phishing, 0 for legitimate). Keep the data file outside Git, for example data/urls.csv, then run:

```powershell
python -m src.train --input data/urls.csv
```

The script prints accuracy, precision, recall, F1, and a confusion matrix, then saves the model to models/phishing_model.joblib. Metrics describe the held-out split of the supplied dataset; duplicates or related domains across splits can cause leakage. For serious evaluation, split by domain and use an independently sourced test set. Never open URLs from the dataset.

## Project structure

```text
PhishGuard-AI/
├── app.py
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── features.py
│   └── train.py
├── tests/
│   ├── __init__.py
│   └── test_features.py
├── data/README.md
├── models/README.md
├── docs/VIVA.md
└── .github/workflows/tests.yml
```

## Privacy and safety

The app parses URL strings locally and does not request submitted destinations. Avoid pasting URLs containing private access tokens or personal data. This project is not a substitute for a reputable security product or human verification.

## License

MIT. See LICENSE.
