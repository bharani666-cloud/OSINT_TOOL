import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dns.resolver

from collectors.email import EmailCollector


def test_email_collector_rejects_invalid_syntax():
    collector = EmailCollector(case_id="TESTCASE")
    result = collector.collect("not-an-email")
    assert len(result.findings) == 0
    assert len(result.errors) == 1


@patch.object(dns.resolver.Resolver, "resolve")
def test_email_collector_identifies_known_provider(mock_resolve):
    mock_resolve.side_effect = dns.resolver.NoAnswer()
    collector = EmailCollector(case_id="TESTCASE")
    result = collector.collect("someone@gmail.com")

    categories = {f.category: f for f in result.findings}
    assert "email_provider" in categories
    assert categories["email_provider"].data["provider"] == "Google (Gmail)"


@patch.object(dns.resolver.Resolver, "resolve")
def test_email_collector_skips_breach_check_without_key(mock_resolve):
    mock_resolve.side_effect = dns.resolver.NoAnswer()
    collector = EmailCollector(case_id="TESTCASE")
    result = collector.collect("someone@example.com")

    breach_findings = [f for f in result.findings if f.category == "breach_notification"]
    assert len(breach_findings) == 1
    assert breach_findings[0].collection_method == "skipped_no_credentials"
