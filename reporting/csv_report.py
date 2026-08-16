"""CSV case export."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from models import CollectionResult

FIELDNAMES = [
    "case_id",
    "category",
    "source",
    "source_url",
    "collection_method",
    "confidence",
    "collected_at",
    "data_json",
]


def write_csv_report(output_path: Path, result: CollectionResult) -> Path:
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        for finding in result.findings:
            writer.writerow(
                {
                    "case_id": finding.case_id,
                    "category": finding.category,
                    "source": finding.source,
                    "source_url": finding.source_url or "",
                    "collection_method": finding.collection_method,
                    "confidence": finding.confidence.value,
                    "collected_at": finding.collected_at,
                    "data_json": json.dumps(finding.data, default=str),
                }
            )
    return output_path
