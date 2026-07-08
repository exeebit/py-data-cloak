"""Streaming format readers/writers for the CLI."""
from .csv_format import process_csv
from .json_format import process_json, process_ndjson
from .sql_format import process_sql

__all__ = ["process_csv", "process_json", "process_ndjson", "process_sql"]


def detect_format(filename: str) -> str:
    name = filename.lower()
    if name.endswith(".csv"):
        return "csv"
    if name.endswith(".jsonl") or name.endswith(".ndjson"):
        return "ndjson"
    if name.endswith(".sql"):
        return "sql"
    return "json"
