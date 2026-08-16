import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.username import UsernameCollector
from models import Confidence


def test_username_collector_rejects_bad_format():
    collector = UsernameCollector(case_id="TESTCASE")
    result = collector.collect("has a space")
    assert len(result.findings) == 0
    assert len(result.errors) == 1


@patch("collectors.username.safe_get")
def test_username_collector_found_profile(mock_safe_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "login": "octocat",
        "name": "The Octocat",
        "bio": "GitHub mascot",
        "blog": "https://github.blog",
        "avatar_url": "https://avatars.githubusercontent.com/u/1",
        "html_url": "https://github.com/octocat",
        "public_repos": 8,
        "followers": 5000,
        "created_at": "2011-01-25T18:44:36Z",
    }
    mock_safe_get.return_value = mock_response

    collector = UsernameCollector(case_id="TESTCASE")
    result = collector.collect("octocat")

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.confidence == Confidence.HIGH
    assert finding.data["username"] == "octocat"


@patch("collectors.username.safe_get")
def test_username_collector_not_found(mock_safe_get):
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_safe_get.return_value = mock_response

    collector = UsernameCollector(case_id="TESTCASE")
    result = collector.collect("definitely_does_not_exist_12345")

    assert len(result.findings) == 1
    assert result.findings[0].data["exists"] is False
    assert result.findings[0].confidence == Confidence.INFO


@patch("collectors.username.safe_get")
def test_username_collector_rate_limited(mock_safe_get):
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_safe_get.return_value = mock_response

    collector = UsernameCollector(case_id="TESTCASE")
    result = collector.collect("someuser")

    assert len(result.errors) == 1
    assert "Rate limited" in result.errors[0].message
