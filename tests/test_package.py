"""Test the main module initialisation code

This should test that reports are generated as expected. The main module is the
point of entry to this whole library so that's what we expect users will be
using.

It's also meant to be used as an CLI tool if called as a script.
"""
import json

import pytest

from dns_deep_state import dns_deep_state
from dns_deep_state.exceptions import DomainError


def test_report_known_tld():
    """Checking a domain that uses one of the known "public suffixes"."""
    reporter = dns_deep_state()

    r = json.loads(reporter.full_report("example.com"))
    assert r["domain"] == "example.com"

    r2 = json.loads(reporter.full_report("www.example.com"))
    assert r2["domain"] == "example.com"

def test_constructor_unknown_tld():
    """Checking a domain that doesn't have one of the "public suffixes"."""
    reporter = dns_deep_state()

    with pytest.raises(DomainError):
        reporter.full_report("blah.patate")
