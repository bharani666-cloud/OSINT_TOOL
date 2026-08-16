import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.phone import PhoneCollector


def test_valid_phone_number_normalizes():
    collector = PhoneCollector(case_id="TESTCASE")
    result = collector.collect("+31612345678")
    assert len(result.errors) == 0
    assert len(result.findings) == 1
    data = result.findings[0].data
    assert data["e164"] == "+31612345678"
    assert data["region"] == "NL"
    assert data["is_valid"] is True


def test_invalid_phone_number_produces_error():
    collector = PhoneCollector(case_id="TESTCASE")
    result = collector.collect("not-a-number")
    assert len(result.findings) == 0
    assert len(result.errors) == 1
