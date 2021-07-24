"""Test the main module initialisation code.

This should test that reports are generated as expected. The main module is the
point of entry to this whole library so that's what we expect users will be
using.

It's also meant to be used as an CLI tool if called as a script.
"""
import json

import pytest

from dns_deep_state import dns_deep_state

from .test_hosts import hosts_file


def test_report_known_tld():
    """Checking a domain that uses one of the known "public suffixes"."""
    reporter = dns_deep_state()
    # TODO stub out calls to full_report on individual probes since that's not
    # what we want to test here

    r = json.loads(reporter.full_report("example.com"))
    assert r["domain"] == "example.com"

    r2 = json.loads(reporter.full_report("www.example.com"))
    assert r2["domain"] == "example.com"


def test_constructor_unknown_tld():
    """Checking a domain that doesn't have one of the "public suffixes"."""
    reporter = dns_deep_state()

    with pytest.raises(ValueError):
        reporter.full_report("blah.patate")


def test_local_hosts_report(mocker):
    """Grab a report for a series of hosts and see that it matches expectations."""
    # We need this mock before initializing the reporter, otherwise the call to
    # the real open() will happen during instantiation
    m = mocker.patch('builtins.open', mocker.mock_open(read_data=hosts_file))
    # We're not testing other resolvers so we want to avoid instantiating them
    mocker.patch("dns_deep_state.PublicSuffixList", mocker.MagicMock)
    mocker.patch("dns_deep_state.DnsProbe", mocker.MagicMock)
    mocker.patch("dns_deep_state.RegistryProbe", mocker.MagicMock)

    reporter = dns_deep_state()
    m.assert_called_once_with("/etc/hosts", "r")

    h_list = ["hostname.fqdn", "remote", "rem", "nope", "192.158.10.25"]

    rep = reporter.local_hosts_report(set(h_list))
    expected = dict(zip(h_list, [True, True, False, False, False]))

    assert isinstance(rep, dict)
    for k, v in expected.items():
        assert v == rep[k]
