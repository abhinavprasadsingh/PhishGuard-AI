from pathlib import Path

import joblib
import numpy as np
import pandas as pd


FEATURES = [
    "url_length",
    "hostname_length",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "at_count",
    "question_count",
    "dash_count",
    "uses_https",
    "has_ip_host",
    "subdomain_count",
    "has_suspicious_word",
    "has_url_shortener",
    "path_length",
    "query_length",
]


def test_committed_model_loads_and_predicts():
    model_path = Path(__file__).resolve().parents[1] / "models" / "phishing_model.joblib"
    assert model_path.is_file() and model_path.stat().st_size > 0

    model = joblib.load(model_path)
    sample = pd.DataFrame(
        [[19, 11, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0]],
        columns=FEATURES,
    )

    prediction = model.predict(sample)
    assert len(prediction) == 1
    assert int(prediction[0]) in (0, 1)

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(sample)
        assert probabilities.shape == (1, 2)
        assert np.isfinite(probabilities).all()
        assert np.isclose(probabilities.sum(axis=1)[0], 1.0)
