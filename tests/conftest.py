"""Keep every CLI test off the network: the spend lookup (CLO-858) would otherwise
try a real Cost Explorer request on the fake test credentials. Tests that
exercise it import the real function themselves (test_score_card.py)."""

import pytest


@pytest.fixture(autouse=True)
def _no_real_spend_lookup(monkeypatch):
    from cloudcostwise import scan

    monkeypatch.setattr(scan, "fetch_monthly_spend", lambda creds, report: None)
    monkeypatch.setattr(scan, "fetch_kms_spend", lambda creds, report: None)
