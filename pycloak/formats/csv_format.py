from __future__ import annotations

import csv
from typing import IO

from ..anonymizer import Anonymizer
from ..exceptions import FormatError


def process_csv(input_file: IO, output_file: IO, anonymizer: Anonymizer) -> int:
    """Stream a CSV file row-by-row. Constant memory."""
    reader = csv.DictReader(input_file)
    if not reader.fieldnames:
        raise FormatError("CSV input must have a header row")

    writer = csv.DictWriter(output_file, fieldnames=reader.fieldnames)
    writer.writeheader()

    count = 0
    for row in reader:
        writer.writerow(anonymizer.process_record(row))
        count += 1
    return count
