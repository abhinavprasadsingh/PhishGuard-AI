# Dataset

Training data is not committed to this repository.
Run `python scripts/prepare_uci_dataset.py` to download UCI PhiUSIIL dataset 967 and create `data/urls.csv` with `url,label` (`0=legitimate`, `1=phishing`). See `../reports/evaluation.md` for attribution and methodology.
The script reads records only and never visits destination URLs. Treat the data as untrusted and do not commit the generated CSV.