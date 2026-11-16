"""Keep every CLI test off the network: the spend lookup (CLO-858) would otherwise
try a real Cost Explorer request on the fake test credentials. Tests that
exercise it import the real function themselves (test_score_card.py)."""

import pytest


@pytest.fixture(autouse=True)
def _no_real_spend_lookup(monkeypatch):
    from cloudcostwise import scan

    monkeypatch.setattr(scan, "fetch_monthly_spend", lambda creds, report: None)
    monkeypatch.setattr(scan, "fetch_kms_spend", lambda creds, report: None)


@pytest.fixture(autouse=True)
def _private_home(tmp_path_factory, monkeypatch):
    """CLO-1055: every real scan now writes ~/.config/cloudcostwise/last-summary.json. Keep the tests'
    scans out of the developer's own home (a test that needs its own HOME sets it again)."""
    monkeypatch.setenv("HOME", str(tmp_path_factory.mktemp("home")))
    monkeypatch.delenv("CLOUDCOSTWISE_SHARE_URL", raising=False)
    monkeypatch.delenv("CLOUDCOSTWISE_SHARE", raising=False)
