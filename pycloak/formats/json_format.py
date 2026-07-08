from __future__ import annotations

import json
from typing import IO, Optional

from ..anonymizer import Anonymizer
from ..exceptions import FormatError


def process_json(input_file: IO, output_file: IO, anonymizer: Anonymizer, indent: Optional[int] = 2) -> int:
    """Process a full JSON document (list or dict).

    Returns the number of records processed.
    """
    try:
        data = json.load(input_file)
    except json.JSONDecodeError as e:
        raise FormatError(f"Invalid JSON: {e}") from e

    if isinstance(data, list):
        processed = [anonymizer.process_record(item) if isinstance(item, dict) else item for item in data]
        count = sum(1 for item in data if isinstance(item, dict))
    elif isinstance(data, dict):
        processed = anonymizer.process_record(data)
        count = 1
    else:
        raise FormatError("JSON root must be a list or dict")

    json.dump(processed, output_file, indent=indent, default=str)
    return count


def process_ndjson(input_file: IO, output_file: IO, anonymizer: Anonymizer) -> int:
    """Stream a JSON-Lines / NDJSON file line-by-line. Constant memory."""
    count = 0
    for line in input_file:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as e:
            raise FormatError(f"Invalid JSON on line {count + 1}: {e}") from e
        if isinstance(record, dict):
            record = anonymizer.process_record(record)
        output_file.write(json.dumps(record, default=str))
        output_file.write("\n")
        count += 1
    return count
