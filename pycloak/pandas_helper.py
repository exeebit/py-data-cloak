"""Optional Pandas integration. Imports lazily so pandas isn't a hard dep."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional

from .anonymizer import Anonymizer

if TYPE_CHECKING:
    import pandas as pd  # noqa: F401


def mask_dataframe(
    df: "pd.DataFrame",
    rules: Optional[Dict[str, Any]] = None,
    *,
    anonymizer: Optional[Anonymizer] = None,
    inplace: bool = False,
    **anonymizer_kwargs: Any,
) -> "pd.DataFrame":
    """Apply masking rules to a pandas DataFrame, column by column.

    Either pass `rules` (a dict) or a pre-built `anonymizer`. Extra kwargs
    (seed, locale, consistent, vault) are forwarded to the Anonymizer.
    """
    try:
        import pandas as pd  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "pandas is not installed. Install it with: pip install \"py-data-cloak[pandas]\""
        ) from e

    if anonymizer is None:
        if rules is None:
            raise ValueError("mask_dataframe requires either rules= or anonymizer=")
        anonymizer = Anonymizer(rules, **anonymizer_kwargs)

    target = df if inplace else df.copy()
    for col in target.columns:
        if anonymizer.matcher.find(str(col)) is None:
            continue
        target[col] = target[col].map(lambda v, _c=str(col): anonymizer.mask_value(_c, v))
    return target
