"""Test DNS verification routines."""
import pytest

from dns_deep_state import dns
from dns_deep_state.exceptions import DomainError, DnsQueryError

from dns.resolver import NoAnswer, NXDOMAIN, YXDOMAIN, NoNameservers
from dns.exception import Timeout


def test_canonical_name(mocker):
    """Request CNAME for a hostname."""
    resolver = dns.DnsProbe()
    stub_resolve = mocker.Mock(
        return_value=mocker.Mock(canonical_name="c.domain.tld"))
    mocker.patch("dns.resolver.Resolver.resolve", stub_resolve)
    canon = resolver.canonical_name("sub.domain.tld")
    assert canon == "c.domain.tld"


def test_canonical_name_not_found(mocker):
    """No result found for requested CNAME."""
    resolver = dns.DnsProbe()
    stub_resolve = mocker.Mock(side_effect=NoAnswer)
    mocker.patch("dns.resolver.Resolver.resolve", stub_resolve)
    canon = resolver.canonical_name("nope.domain.tld")
    assert canon is None


def test_name_servers(mocker):
    """Request NS for a hostname."""
    name_servers = {"ns1.domain.tld", "ns2.domain.tld", "ns3.domain.tld"}
    name_server_texts = mocker.Mock(side_effect=name_servers)
    mock_rrset = [
        mocker.Mock(to_text=name_server_texts),
        mocker.Mock(to_text=name_server_texts),
        mocker.Mock(to_text=name_server_texts)]
    stub_resolve = mocker.Mock(return_value=mocker.Mock(rrset=mock_rrset))
    mocker.patch("dns.resolver.Resolver.resolve", stub_resolve)
    resolver = dns.DnsProbe()
    ns = resolver.name_servers("domain.tld")
    assert ns == name_servers


def test_soa(mocker):
    """Request SOA for a hostname from a specific nameserver."""
    expected = {
        "mname": "ns1.domain.tld",
        "rname": "hostmaster.domain.tld",
        "serial": "1630021470",
        "refresh": "86400",
        "retry": "7200",
        "expire": "4000000",
        "ttl": "11200",
    }

    lib_rr_params = {
        "mname": mocker.Mock(
            to_text=mocker.Mock(return_value=expected["mname"])),
        "rname": mocker.Mock(
            to_text=mocker.Mock(return_value=expected["rname"])),
        "serial": expected["serial"],
        "refresh": expected["refresh"],
        "retry": expected["retry"],
        "expire": expected["expire"],
        "minimum": expected["ttl"],
    }

    mock_rr = mocker.Mock(**lib_rr_params)
    mock_soa = mocker.Mock(rrset=[mock_rr])
    stub_resolve = mocker.Mock(return_value=mock_soa)
    mocker.patch("dns.resolver.Resolver.resolve", stub_resolve)

    resolver = dns.DnsProbe()
    soa = resolver.soa("domain.tld", "ns1.domain.tld")

    assert soa == expected


def test_v4_address(mocker):
    """Get the IPv4 address of a hostname."""
    ip_address = "127.0.0.98"
    mock_rr = mocker.Mock(to_text=mocker.Mock(return_value=ip_address))
    mock_answer = mocker.Mock(rrset=[mock_rr])
    stub_resolve = mocker.Mock(return_value=mock_answer)
    mocker.patch("dns.resolver.Resolver.resolve", stub_resolve)

    resolver = dns.DnsProbe()
    v4a = resolver.v4_address("domain.tld")

    assert v4a == [ip_address]


@pytest.mark.parametrize("raised_excpt,expected_excpt",
                         [(NXDOMAIN, DomainError),
                          (NoNameservers, DomainError),
                          (YXDOMAIN, DnsQueryError),
                          (Timeout, DnsQueryError)])
def test_lookup_server_error(mocker, raised_excpt, expected_excpt):
    """No result found or no nameserver."""
    resolver = dns.DnsProbe()
    stub_resolve = mocker.Mock(side_effect=raised_excpt)
    mocker.patch("dns.resolver.Resolver.resolve", stub_resolve)
    with pytest.raises(expected_excpt):
        resolver.lookup("nope.domain.tld", "A")


def test_set_nameservers():
    """Change the list of probed nameservers."""
    resolver = dns.DnsProbe()
    resolver._set_nameservers(['1.2.3.4', '9.8.7.6'])

    assert resolver.res.nameservers == ['1.2.3.4', '9.8.7.6']


def test_reset_nameservers():
    """Put previously known nameservers back in place."""
    resolver = dns.DnsProbe()
    resolver.res.nameservers = ['10.10.10.10', '10.20.30.40']
    resolver._saved_name_servers = ['192.168.99.66']

    resolver._reset_nameservers()

    assert resolver.res.nameservers == ['192.168.99.66']


def test_reset_nameservers_nothing_known():
    """Trying to reset nameservers but nothing previously known."""
    resolver = dns.DnsProbe()
    resolver.res.nameservers = ['5.5.5.5', '42.42.42.42']
    # This is the default, but we'll still just force the scenario in place.
    resolver._saved_name_servers = None

    resolver._reset_nameservers()

    assert resolver.res.nameservers == ['5.5.5.5', '42.42.42.42']
