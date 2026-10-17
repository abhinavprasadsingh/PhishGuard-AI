"""Helpers for safely exporting user-controlled text to CSV files."""

import pandas as pd


_FORMULA_PREFIXES = ("=", "+", "-", "@")


def sanitize_csv_for_spreadsheet(dataframe: pd.DataFrame) -> pd.DataFrame:
    """Return a copy with formula-like text cells prefixed to discourage execution.

    CSV quoting alone does not prevent spreadsheet formula injection. This
    function is for exported reports only; it does not alter displayed results.
    """
    safe = dataframe.copy()

    def sanitize(value):
        if not isinstance(value, str):
            return value
        # Ignore leading whitespace/control characters when checking for a
        # formula prefix, but preserve the original text after the apostrophe.
        if value.lstrip(" \t\r\n").startswith(_FORMULA_PREFIXES):
            return "'" + value
        return value

    for column in safe.columns:
        if safe[column].dtype == object or pd.api.types.is_string_dtype(safe[column].dtype):
            safe[column] = safe[column].map(sanitize)
    return safe
