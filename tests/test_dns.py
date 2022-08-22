"""Test DNS verification routines."""
import pytest

from dns_deep_state import dns
from dns_deep_state.exceptions import DomainError, DnsQueryError

from dns.resolver import NoAnswer, NXDOMAIN, YXDOMAIN, NoNameservers
from dns.exception import Timeout


def test__ipv6_conectivity(mocker):
    """IPv6 connectivity is possible."""
    m = mocker.patch('socket.socket.connect', mocker.Mock())
    resolver = dns.DnsProbe()

    m.assert_called_once()

    assert resolver.ipv6_enabled is True


def test__socket_no_ipv6(mocker):
    """The socket module does not have IPv6 capabilities."""
    mocker.patch('socket.has_ipv6', False)
    resolver = dns.DnsProbe()

    assert resolver.ipv6_enabled is False


def test__failed_ipv6_conectivity(mocker):
    """IPv6 connectivity is not possible."""
    m = mocker.patch('socket.socket.connect', mocker.Mock(side_effect=OSError))
    resolver = dns.DnsProbe()

    m.assert_called_once()

    assert resolver.ipv6_enabled is False


def test_canonical_name(mocker):
    """Request CNAME for a hostname."""
    mocker.patch('dns_deep_state.dns.DnsProbe._ipv6_connectivity',
                 mocker.Mock(return_value=True))
    resolver = dns.DnsProbe()
    stub_lookup = mocker.Mock(
        return_value=mocker.Mock(canonical_name="c.domain.tld"))
    mocker.patch("dns_deep_state.dns.DnsProbe.lookup", stub_lookup)
    canon = resolver.canonical_name("sub.domain.tld")

    stub_lookup.assert_called_once_with("sub.domain.tld", "CNAME")
    assert canon == "c.domain.tld"


def test_canonical_name_not_found(mocker):
    """No result found for requested CNAME."""
    mocker.patch('dns_deep_state.dns.DnsProbe._ipv6_connectivity',
                 mocker.Mock(return_value=True))
    resolver = dns.DnsProbe()
    stub_lookup = mocker.Mock(side_effect=NoAnswer)
    mocker.patch("dns_deep_state.dns.DnsProbe.lookup", stub_lookup)
    canon = resolver.canonical_name("nope.domain.tld")

    stub_lookup.assert_called_once_with("nope.domain.tld", "CNAME")
    assert canon is None


def test_name_servers(mocker):
    """Request NS for a hostname."""
    name_servers = {"ns1.domain.tld", "ns2.domain.tld", "ns3.domain.tld"}
    name_server_texts = mocker.Mock(side_effect=name_servers)
    mock_rrset = [
        mocker.Mock(to_text=name_server_texts),
        mocker.Mock(to_text=name_server_texts),
        mocker.Mock(to_text=name_server_texts)]
    stub_lookup = mocker.Mock(return_value=mocker.Mock(rrset=mock_rrset))
    mocker.patch("dns_deep_state.dns.DnsProbe.lookup", stub_lookup)
    mocker.patch('dns_deep_state.dns.DnsProbe._ipv6_connectivity',
                 mocker.Mock(return_value=True))
    resolver = dns.DnsProbe()
    ns = resolver.name_servers("domain.tld")

    stub_lookup.assert_called_once_with("domain.tld", "NS")
    assert ns == name_servers


def test_soa(mocker):
    """Request SOA for a hostname from a specific nameserver."""
    expected = {
        "mname": "ns1.example.com",
        "rname": "hostmaster.example.com",
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
    mock_answer = mocker.Mock(rrset=[mock_rr])
    stub_lookup = mocker.Mock(return_value=mock_answer)
    mocker.patch("dns_deep_state.dns.DnsProbe.lookup", stub_lookup)

    mocker.patch('dns_deep_state.dns.DnsProbe._ipv6_connectivity',
                 mocker.Mock(return_value=True))
    resolver = dns.DnsProbe()
    soa = resolver.soa("example.com", "127.1.2.3")

    stub_lookup.assert_called_once_with("example.com", "SOA", server_ip="127.1.2.3")
    assert soa == expected


@pytest.mark.parametrize("ip_address,rr_type,method_name",
                         [("127.0.0.98", "A", "v4_address"),
                          ("fe80::98", "AAAA", "v6_address")])
def test_v46_address(mocker, ip_address, rr_type, method_name):
    """Successfully get the IPv4 or IPv6 address of a hostname."""
    mock_rr = mocker.Mock(to_text=mocker.Mock(return_value=ip_address))
    mock_answer = mocker.Mock(rrset=[mock_rr])
    stub_lookup = mocker.Mock(return_value=mock_answer)
    mocker.patch("dns_deep_state.dns.DnsProbe.lookup", stub_lookup)

    mocker.patch('dns_deep_state.dns.DnsProbe._ipv6_connectivity',
                 mocker.Mock(return_value=True))
    resolver = dns.DnsProbe()
    lookup_method = getattr(resolver, method_name)
    resd_addr = lookup_method("domain.tld")

    stub_lookup.assert_called_once_with("domain.tld", rr_type)

    assert resd_addr == [ip_address]


@pytest.mark.parametrize("raised_excpt,expected_excpt",
                         [(NXDOMAIN, DomainError),
                          (NoNameservers, DomainError),
                          (YXDOMAIN, DnsQueryError),
                          (Timeout, DnsQueryError)])
def test_lookup_server_error(mocker, raised_excpt, expected_excpt):
    """No result found or no nameserver."""
    mocker.patch('dns_deep_state.dns.DnsProbe._ipv6_connectivity',
                 mocker.Mock(return_value=True))
    resolver = dns.DnsProbe()
    stub_resolve = mocker.Mock(side_effect=raised_excpt)
    mocker.patch("dns.resolver.Resolver.resolve", stub_resolve)
    with pytest.raises(expected_excpt):
        resolver.lookup("nope.domain.tld", "A")


@pytest.mark.parametrize("ns_ip", [None, '127.1.2.3'])
def test_lookup(mocker, ns_ip):
    """Run a DNS lookup of a certain type and get a response back."""
    mocker.patch('dns_deep_state.dns.DnsProbe._ipv6_connectivity',
                 mocker.Mock(return_value=True))

    fake_response = mocker.Mock()
    stub_resolve = mocker.Mock(return_value=fake_response)
    mocker.patch("dns.resolver.Resolver.resolve", stub_resolve)

    resolver = dns.DnsProbe()
    default_name_servers = resolver.res.nameservers

    result = resolver.lookup('yep.domain.tld', 'A', ns_ip)

    # this may have been changed during the function call but in all cases it
    # should be set back to the original value once the lookup is finished.
    assert resolver.res.nameservers == default_name_servers
    # the actual value is not important, but as long as the return value is the
    # same thing as what gets returned by the actual dns lookup
    assert result == fake_response


def test_set_nameservers(mocker):
    """Change the list of probed nameservers."""
    mocker.patch('dns_deep_state.dns.DnsProbe._ipv6_connectivity',
                 mocker.Mock(return_value=True))
    resolver = dns.DnsProbe()
    resolver._set_nameservers(['1.2.3.4', '9.8.7.6'])

    assert resolver.res.nameservers == ['1.2.3.4', '9.8.7.6']


def test_reset_nameservers(mocker):
    """Put previously known nameservers back in place."""
    mocker.patch('dns_deep_state.dns.DnsProbe._ipv6_connectivity',
                 mocker.Mock(return_value=True))
    resolver = dns.DnsProbe()
    resolver.res.nameservers = ['10.10.10.10', '10.20.30.40']
    resolver._saved_name_servers = ['192.168.99.66']

    resolver._reset_nameservers()

    assert resolver.res.nameservers == ['192.168.99.66']


def test_reset_nameservers_nothing_known(mocker):
    """Trying to reset nameservers but nothing previously known."""
    mocker.patch('dns_deep_state.dns.DnsProbe._ipv6_connectivity',
                 mocker.Mock(return_value=True))
    resolver = dns.DnsProbe()
    resolver.res.nameservers = ['5.5.5.5', '42.42.42.42']
    # This is the default, but we'll still just force the scenario in place.
    resolver._saved_name_servers = None

    resolver._reset_nameservers()

    assert resolver.res.nameservers == ['5.5.5.5', '42.42.42.42']
