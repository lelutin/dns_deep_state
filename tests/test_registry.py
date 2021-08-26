"""Test domain registry querying."""
import pytest

from dns_deep_state.exceptions import DomainError
from dns_deep_state.registry import RegistryProbe
import whoisit.errors


# It's not really necessary to have something so realistic, but it gives a
# good idea of the expected format for the returned data structure. This is
# directly the data structure returned by the whoisit library since it
# makes a lot of sense.
#
# Note, however, that the ToS URL has been shortened and the registration
# dates are strings instead of datetime objects.
expected_rdap_info = {
    'handle': '2336799_DOMAIN_COM-VRSN',
    'parent_handle': '',
    'name': 'EXAMPLE.COM',
    'whois_server': '',
    'type': 'domain',
    'terms_of_service_url': 'https://www.verisign.com/domain-names/...',
    'copyright_notice': '',
    'description': [],
    'last_changed_date': None,
    'registration_date': "1995-8-14",
    'expiration_date': "2021-8-13",
    'url': 'https://rdap.verisign.com/com/v1/domain/EXAMPLE.COM',
    'rir': '',
    'entities': {
        'registrar': [{
            'handle': '376',
            'type': 'entity',
            'name': 'RESERVED-Internet Assigned Numbers Authority'}]},
    'nameservers': ['A.IANA-SERVERS.NET', 'B.IANA-SERVERS.NET'],
    'status': ['client delete prohibited',
               'client transfer prohibited',
               'client update prohibited']}


def test_domain_info_from_rdap(mocker):
    """Request information about a domain and get it from RDAP."""
    module_mock = mocker.MagicMock(bootstrap=mocker.Mock)
    mocker.patch("dns_deep_state.registry.whoisit", module_mock)
    reg = RegistryProbe()

    module_mock.domain = mocker.Mock(return_value=expected_rdap_info)

    info = reg.domain_name("example.com")

    assert info == expected_rdap_info


def test_domain_info_unregistered(mocker):
    """Request information for a domain that is not currently registered."""
    raised_exc = whoisit.errors.ResourceDoesNotExist
    module_mock = mocker.MagicMock(
        bootstrap=mocker.Mock,
        errors=whoisit.errors)
    mocker.patch("dns_deep_state.registry.whoisit", module_mock)
    reg = RegistryProbe()

    module_mock.domain = mocker.Mock(side_effect=raised_exc)
    with pytest.raises(DomainError):
        reg.domain_name("somethingnotthere.com")


def test_domain_rdap_server_weak_ssl(mocker):
    """Replies from RDAP servers with too weak ssl should still function."""
    raised_exc = whoisit.errors.QueryError(
        "Failed to make a GET request to "
        "https://rdap.nominet.uk/work/domain/nic.work: "
        "HTTPSConnectionPool(host='rdap.nominet.uk', port=443): Max retries "
        "exceeded with url: /work/domain/nic.work (Caused by "
        "SSLError(SSLError(1, '[SSL: DH_KEY_TOO_SMALL] dh key too small "
        "(_ssl.c:1123)')))")
    domain_method = mocker.Mock(
        side_effect=[raised_exc, expected_rdap_info])

    module_mock = mocker.MagicMock(
        bootstrap=mocker.Mock,
        errors=whoisit.errors,
        domain=domain_method)
    mocker.patch("dns_deep_state.registry.whoisit", module_mock)

    reg = RegistryProbe()

    info = reg.domain_name("nic.work")

    assert info == expected_rdap_info
