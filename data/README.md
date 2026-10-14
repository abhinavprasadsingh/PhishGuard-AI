# Dataset instructions

No dataset is bundled or fabricated. To train a supervised model, obtain a labeled URL dataset from a reputable source and confirm its license, provenance, and permitted use.

Prepare a CSV with:
- `url`: the URL string
- `label`: 1 for phishing and 0 for legitimate

Keep downloaded datasets out of Git. Review duplicates and class balance, split data before model selection, and avoid putting the same domain or near-duplicate URL in both train and test where possible. Never fetch or open the URLs in the dataset.
