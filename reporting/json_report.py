"""JSON case export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from models import CollectionResult, utc_now_iso


def write_json_report(
    output_path: Path,
    case_id: str,
    inputs: dict[str, Any],
    result: CollectionResult,
    reference: str | None = None,
) -> Path:
    payload = {
        "case_id": case_id,
        "reference": reference,
        "generated_at": utc_now_iso(),
        "inputs": inputs,
        "summary": {
            "sources_queried": result.sources_queried,
            "findings_count": len(result.findings),
            "errors_count": len(result.errors),
        },
        "findings": [f.to_dict() for f in result.findings],
        "errors": [e.to_dict() for e in result.errors],
    }
    output_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return output_path
