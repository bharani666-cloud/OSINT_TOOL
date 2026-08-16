import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dns.resolver

from collectors.dns import DNSCollector


class _FakeAnswer:
    def __init__(self, value):
        self._value = value

    def __str__(self):
        return self._value


def test_dns_collector_rejects_invalid_domain():
    collector = DNSCollector(case_id="TESTCASE")
    result = collector.collect("not a domain!!")
    assert len(result.findings) == 0
    assert len(result.errors) == 1
    assert "not a valid domain" in result.errors[0].message


@patch("collectors.dns.safe_get")
@patch("collectors.dns.resolve_hostname", return_value=[])
@patch.object(dns.resolver.Resolver, "resolve")
def test_dns_collector_handles_records_and_nxdomain(mock_resolve, mock_resolve_hostname, mock_safe_get):
    # Simulate A record success, then NXDOMAIN partway through record types.
    def side_effect(domain, record_type):
        if record_type == "A":
            return [_FakeAnswer("93.184.216.34")]
        raise dns.resolver.NXDOMAIN()

    mock_resolve.side_effect = side_effect
    mock_response = MagicMock(status_code=404)
    mock_safe_get.return_value = mock_response

    collector = DNSCollector(case_id="TESTCASE")
    result = collector.collect("example.com")

    categories = [f.category for f in result.findings]
    assert "dns_record" in categories
    assert any(e.source == "dns" for e in result.errors)
