"""Test the main module initialisation code.

This should test that reports are generated as expected. The main module is the
point of entry to this whole library so that's what we expect users will be
using.

It's also meant to be used as an CLI tool if called as a script.
"""
import copy
import json
from itertools import chain

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
    if probe_used not in probes.keys():
        raise Exception("Unknown probe {probe_used}")

    for name, func in probes.items():
        if name != probe_used:
            # Mock out any probe that wasn't requested for testing
            mocker.patch(func, mocker.MagicMock)

    if probe_used == "dns":
        mocker.patch('dns_deep_state.dns.DnsProbe._ipv6_connectivity',
                     mocker.Mock(return_value=True))

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
            f"{patch_prefix}.DomainReport.{name}_report",
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
    # In this scenario, all is going fine so we'll always return the same SOA
    # structure.
    soa_response = {"serial": "199974862"}
    reporter.dns.soa = mocker.Mock(return_value=soa_response)

    ns_v4_ips = [["127.0.0.121"], ["127.0.0.122"], ["127.0.0.123"]]
    reporter.dns.v4_address = mocker.Mock(side_effect=copy.deepcopy(ns_v4_ips))
    ns_v6_ips = [["fe80::a"], ["fe80::b"], ["fe80::c"]]
    reporter.dns.v6_address = mocker.Mock(side_effect=copy.deepcopy(ns_v6_ips))

    r = reporter.dns_report("example.com")

    # All went well: got one IPv4 and one IPv6 for each nameserver and all
    # responded with the same soa record information
    assert len(r["nameservers"]) == 6
    assert {x["hostname"] for x in r["nameservers"]} == name_servers

    all_found_ns_ips = [x["ip_address"] for x in r["nameservers"]]
    all_ips = list(chain.from_iterable(ns_v4_ips)) + list(chain.from_iterable(ns_v6_ips))
    assert len(all_found_ns_ips) == len(all_ips)
    assert set(all_found_ns_ips) == set(all_ips)

    for ns in r["nameservers"]:
        assert ns["soa"]["serial"] == soa_response["serial"]


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
