import pandas as pd
import pytest

from src.csv_safety import sanitize_csv_for_spreadsheet


@pytest.mark.parametrize("value", [
    "=1+1",
    "+SUM(A1:A2)",
    "-1+2",
    "@SUM(A1:A2)",
    "  =1+1",
    "\t=1+1",
    "\r@SUM(A1:A2)",
])
def test_formula_like_text_is_prefixed(value):
    frame = pd.DataFrame({"Input URL": [value]})
    safe = sanitize_csv_for_spreadsheet(frame)
    assert safe.loc[0, "Input URL"] == "'" + value


@pytest.mark.parametrize("value", [
    "https://example.com",
    "http://example.com/login?next=home",
    "ordinary text",
    "",
])
def test_regular_text_is_unchanged(value):
    frame = pd.DataFrame({"Input URL": [value]})
    safe = sanitize_csv_for_spreadsheet(frame)
    assert safe.loc[0, "Input URL"] == value


def test_does_not_mutate_original_dataframe():
    frame = pd.DataFrame({"Input URL": ["=1+1"]})
    safe = sanitize_csv_for_spreadsheet(frame)
    assert frame.loc[0, "Input URL"] == "=1+1"
    assert safe.loc[0, "Input URL"] == "'=1+1"


def test_non_text_values_are_preserved():
    frame = pd.DataFrame({"score": [42], "confidence": [0.95]})
    safe = sanitize_csv_for_spreadsheet(frame)
    assert safe.equals(frame)
