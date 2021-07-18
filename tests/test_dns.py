"""Test DNS verification routines."""
import pytest

from dns_deep_state import dns
from dns_deep_state.exceptions import DomainError, DnsQueryError

from dns.resolver import NoAnswer, NXDOMAIN, YXDOMAIN, NoNameservers
from dns.exception import Timeout


def test_canonical_name(mocker):
    """Request CNAME for a hostname."""
    resolver = dns.DnsProbe()
    stub_resolve = mocker.Mock(return_value=mocker.Mock(canonical_name="c.domain.tld"))
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


@pytest.mark.parametrize("raised_excpt,expected_excpt",
                         [(NXDOMAIN, DomainError), (NoNameservers, DomainError),
                          (YXDOMAIN, DnsQueryError), (Timeout, DnsQueryError)])
def test_lookup_server_error(mocker, raised_excpt, expected_excpt):
    """No result found or no nameserver."""
    resolver = dns.DnsProbe()
    stub_resolve = mocker.Mock(side_effect=raised_excpt)
    mocker.patch("dns.resolver.Resolver.resolve", stub_resolve)
    with pytest.raises(expected_excpt):
        resolver.lookup("nope.domain.tld", "A")
