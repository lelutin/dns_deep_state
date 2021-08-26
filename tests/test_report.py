"""Test the main module initialisation code.

This should test that reports are generated as expected. The main module is the
point of entry to this whole library so that's what we expect users will be
using.

It's also meant to be used as an CLI tool if called as a script.
"""
import json

import pytest

from dns_deep_state.report import DomainReport
from dns_deep_state.exceptions import DomainError

from .test_hosts import hosts_file
from .test_registry import expected_rdap_info


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
        "local_hosts": "dns_deep_state.report.HostsProbe",
    }

    for name, func in probes.items():
        if name != probe_used:
            # Mock out any probe that wasn't requested for testing
            mocker.patch(func, mocker.MagicMock)

    return DomainReport()


def test_full_report_known_tld(mocker):
    """Checking a domain that uses one of the known "public suffixes".

    Note that we're only testing the processing that the full_report() method
    itself is doing, not any of the probe reports.
    """
    # We still need to return an empty report for mocked out probes
    # for the tests on full_report() itself to be coherent.
    # Otherwise we get side-effects from the mocks themselves.
    patch_prefix = "dns_deep_state.report"
    for name in ["registry", "dns", "local_hosts"]:
        mocker.patch(
            "{}.DomainReport.{}_report".format(patch_prefix, name),
            mocker.Mock(return_value={}))
    reporter = domain_report_mocked_probes(mocker, probe_used="psl")

    r = json.loads(reporter.full_report("example.com"))
    assert r["domain"] == "example.com"

    r2 = json.loads(reporter.full_report("www.example.com"))
    assert r2["domain"] == "example.com"


def test_full_report_unknown_tld(mocker):
    """Checking a domain that doesn't have one of the "public suffixes".

    Note that we're only testing the processing that the full_report() method
    itself is doing, not any of the probe reports.
    """
    reporter = domain_report_mocked_probes(mocker, probe_used="psl")

    with pytest.raises(ValueError):
        reporter.full_report("blah.patate")


def test_registry_report(mocker):
    """Get a registry report for an existing domain name."""
    module_mock = mocker.MagicMock(bootstrap=mocker.Mock)
    module_mock.domain = mocker.Mock(return_value=expected_rdap_info)
    mocker.patch("dns_deep_state.registry.whoisit", module_mock)
    reporter = domain_report_mocked_probes(mocker, probe_used="registry")

    r = reporter.registry_report("example.com")
    # The report should not contain all of the information returned by the
    # database. Only those informations help us determine if something's wrong
    # with the registration.
    assert len(r) == 4
    assert r["status"] == expected_rdap_info["status"]
    assert r["expiration_date"] == expected_rdap_info["expiration_date"]
    expctd_reg = expected_rdap_info["entities"]["registrar"][0]["name"]
    assert r["registrar"] == expctd_reg
    assert r["nameservers"] == expected_rdap_info["nameservers"]


def test_dns_report_no_nameservers(mocker):
    """Can't find nameservers in DNS zone."""
    raised_exc = DomainError(
        "No nameservers were found in DNS for example.com")
    dns_lookup = mocker.Mock(side_effect=raised_exc)
    mocker.patch("dns_deep_state.report.DnsProbe.name_servers", dns_lookup)
    reporter = domain_report_mocked_probes(mocker, probe_used="dns")

    with pytest.raises(DomainError):
        reporter.dns_report("example.com")


def test_dns_report(mocker):
    """Get all probed DNS information as a report."""
    reporter = domain_report_mocked_probes(mocker, probe_used="dns")

    # We don't care at this level how the lookup is implemented. We only care
    # that when certain name servers are returned we get the proper form of
    # report.
    name_servers = {"ns1.example.com", "ns2.example.com", "ns3.example.com"}
    dns_lookup = mocker.Mock(return_value=name_servers)
    reporter.dns.name_servers = dns_lookup

    r = reporter.dns_report("example.com")

    assert len(r["nameservers"]) == 3
    # each entry should be a dictionary with
    #   one key "hostname"
    #   one key "soa_serial"
    # a set of all "hostname" keys should be identical to mock servers


def test_local_hosts_report(mocker):
    """Check presence in local hosts for a series of hosts.

    We want to see whether requesting multiple informations at once functions
    properly. That's why we're not parametrizing fixtures and checking them one
    at a time.
    """
    # We need this mock before initializing the reporter, otherwise the call to
    # the real open() will happen during instantiation
    m = mocker.patch('builtins.open', mocker.mock_open(read_data=hosts_file))
    reporter = domain_report_mocked_probes(mocker, probe_used="local_hosts")
    m.assert_called_once_with("/etc/hosts", "r")

    h_list = ["hostname.fqdn", "remote", "rem", "nope", "192.158.10.25"]

    rep = reporter.local_hosts_report(set(h_list))
    expected = dict(zip(h_list, [True, True, False, False, False]))

    assert isinstance(rep, dict)
    for k, v in expected.items():
        assert v == rep[k]
