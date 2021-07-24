"""Test the main module initialisation code.

This should test that reports are generated as expected. The main module is the
point of entry to this whole library so that's what we expect users will be
using.

It's also meant to be used as an CLI tool if called as a script.
"""
import json

import pytest

from dns_deep_state.report import DomainReport

from .test_hosts import hosts_file


def domain_report_mocked_probes(mocker, probe_used=None):
    """Instantiate DomainReport and mock out probes.

    If probe_used is not None, then one probe will be left untouched.

    Most probes tend to initialize some connection, or read a file in order to
    be ready to query something for information. When we're testing out
    individual reports, we don't need to initialize the probes that are not
    checked on every test. Also this initialization step can add up to consume
    quite a lot of time. We'll only test one desired probe at a time to keep
    the tests focused and quicker.
    """
    probes = {
        "psl": "dns_deep_state.report.PublicSuffixList",
        "registry": "dns_deep_state.report.RegistryProbe",
        "dns": "dns_deep_state.report.DnsProbe",
        "hosts": "dns_deep_state.report.HostsProbe",
    }

    for name, func in probes.items():
        if name != probe_used:
            # Mock out any probe that wasn't requested for testing
            mocker.patch(func, mocker.MagicMock)

    return DomainReport()


def test_report_known_tld(mocker):
    """Checking a domain that uses one of the known "public suffixes"."""
    reporter = domain_report_mocked_probes(mocker, probe_used="psl")

    r = json.loads(reporter.full_report("example.com"))
    assert r["domain"] == "example.com"

    r2 = json.loads(reporter.full_report("www.example.com"))
    assert r2["domain"] == "example.com"


def test_constructor_unknown_tld(mocker):
    """Checking a domain that doesn't have one of the "public suffixes"."""
    reporter = domain_report_mocked_probes(mocker, probe_used="psl")

    with pytest.raises(ValueError):
        reporter.full_report("blah.patate")


def test_local_hosts_report(mocker):
    """Check presence in local hosts for a series of hosts.

    We want to see whether requesting multiple informations at once functions
    properly. That's why we're not parametrizing fixtures and checking them one
    at a time.
    """
    # We need this mock before initializing the reporter, otherwise the call to
    # the real open() will happen during instantiation
    m = mocker.patch('builtins.open', mocker.mock_open(read_data=hosts_file))
    reporter = domain_report_mocked_probes(mocker, probe_used="hosts")
    m.assert_called_once_with("/etc/hosts", "r")

    h_list = ["hostname.fqdn", "remote", "rem", "nope", "192.158.10.25"]

    rep = reporter.local_hosts_report(set(h_list))
    expected = dict(zip(h_list, [True, True, False, False, False]))

    assert isinstance(rep, dict)
    for k, v in expected.items():
        assert v == rep[k]
