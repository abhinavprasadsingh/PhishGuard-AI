"""Prepare URL-only labeled data from UCI PhiUSIIL dataset 967."""
from pathlib import Path
import pandas as pd
from ucimlrepo import fetch_ucirepo

OUT = Path("data/urls.csv")

def main():
    dataset = fetch_ucirepo(id=967)
    features, targets = dataset.data.features, dataset.data.targets
    if "URL" not in features.columns:
        raise SystemExit(f"Expected URL column; got {list(features.columns)}")
    target_col = "label" if "label" in targets.columns else targets.columns[0]
    frame = pd.DataFrame({"url": features["URL"], "uci_label": pd.to_numeric(targets[target_col], errors="coerce")})
    frame = frame.dropna(subset=["url", "uci_label"])
    frame["url"] = frame["url"].astype(str).str.strip()
    frame = frame[(frame["url"] != "") & frame["uci_label"].isin([0, 1])]
    # UCI: 1=legitimate, 0=phishing. Project: 0=legitimate, 1=phishing.
    frame["label"] = frame["uci_label"].map({1: 0, 0: 1}).astype(int)
    frame = frame[["url", "label"]].drop_duplicates(subset=["url"])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(OUT, index=False)
    print(f"Saved {len(frame)} unique URLs to {OUT}")
    print("Labels (0=legitimate, 1=phishing):")
    print(frame["label"].value_counts().sort_index().to_string())
    print("Source: UCI PhiUSIIL dataset 967, DOI 10.1016/j.cose.2023.103545")
    print("Only URL text and labels are exported; destination URLs are never visited.")

if __name__ == "__main__":
    main()