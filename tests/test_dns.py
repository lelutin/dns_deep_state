"""Test DNS verification routines."""
import pytest

from dns_deep_state import dns
from dns_deep_state.exceptions import DomainError

from dns.resolver import NoAnswer, NXDOMAIN, NoNameservers


def test_constructor_known_tld():
    """Checking a domain that uses one of the known "public suffixes"."""
    r = dns.Dns("example.com")
    assert r.domain_name == "example.com"

    r2 = dns.Dns("www.example.com")
    assert r2.domain_name == "example.com"

def test_constructor_unknown_tld():
    """Checking a domain that doesn't have one of the "public suffixes"."""
    with pytest.raises(DomainError):
        dns.Dns("blah.patate")


def resolver_without_psl(mocker):
    """Create a DNS resolver but disable Public Suffix checking.

    The PublicSuffixList object parses the psl data file each time it is
    created and this adds some useless processing time to the tests.

    The PSL check behavior is already getting tested through the class
    constructor.
    """
    stub_suffix = mocker.Mock()
    mocker.patch("dns_deep_state.dns.PublicSuffixList", stub_suffix)
    return dns.Dns("domain.com")

def test_canonical_name(mocker):
    """Request CNAME for a hostname."""
    resolver = resolver_without_psl(mocker)
    stub_resolve = mocker.Mock(return_value=mocker.Mock(canonical_name="c.domain.tld"))
    mocker.patch("dns.resolver.Resolver.resolve", stub_resolve)
    canon = resolver.canonical_name("sub.domain.tld")
    assert canon == "c.domain.tld"

def test_canonical_name_not_found(mocker):
    """No result found for requested CNAME."""
    resolver = resolver_without_psl(mocker)
    stub_resolve = mocker.Mock(side_effect=NoAnswer)
    mocker.patch("dns.resolver.Resolver.resolve", stub_resolve)
    canon = resolver.canonical_name("nope.domain.tld")
    assert canon == None

@pytest.mark.parametrize("exception", [NXDOMAIN, NoNameservers])
def test_canonical_name_server_error(mocker, exception):
    """No result found or no nameserver."""
    resolver = resolver_without_psl(mocker)
    stub_resolve = mocker.Mock(side_effect=exception)
    mocker.patch("dns.resolver.Resolver.resolve", stub_resolve)
    with pytest.raises(DomainError):
        resolver.canonical_name("nope.domain.tld")
