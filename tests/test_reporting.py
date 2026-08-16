import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models import CollectionResult, CollectionError, Finding, Confidence
from reporting.json_report import write_json_report
from reporting.csv_report import write_csv_report
from reporting.html_report import write_html_report


def _sample_result() -> CollectionResult:
    result = CollectionResult(sources_queried=2)
    result.findings.append(
        Finding(
            category="dns_record",
            source="DNS (A)",
            source_url=None,
            collection_method="dns_query",
            confidence=Confidence.HIGH,
            data={"domain": "example.com", "values": ["93.184.216.34"]},
            case_id="TESTCASE",
        )
    )
    result.errors.append(CollectionError(source="rdap", message="timeout", case_id="TESTCASE"))
    return result


def test_write_json_report(tmp_path):
    out = write_json_report(tmp_path / "report.json", "TESTCASE", {"domain": "example.com"}, _sample_result())
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["case_id"] == "TESTCASE"
    assert payload["summary"]["findings_count"] == 1
    assert payload["summary"]["errors_count"] == 1


def test_write_csv_report(tmp_path):
    out = write_csv_report(tmp_path / "report.csv", _sample_result())
    content = out.read_text(encoding="utf-8")
    assert "dns_record" in content
    assert "DNS (A)" in content


def test_write_html_report(tmp_path):
    out = write_html_report(tmp_path / "report.html", "TESTCASE", {"domain": "example.com"}, _sample_result())
    content = out.read_text(encoding="utf-8")
    assert "Authorized OSINT Investigation Report" in content
    assert "dns_record" in content
    assert "HIGH" in content
