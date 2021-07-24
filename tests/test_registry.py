"""Test domain registry querying."""
from dns_deep_state.registry import RegistryProbe


def test_domain_info_from_rdap(mocker):
    """Request information about a domain and get it from RDAP."""
    module_mock = mocker.MagicMock(bootstrap=mocker.Mock)
    mocker.patch("dns_deep_state.registry.whoisit", module_mock)
    reg = RegistryProbe()

    # It's not really necessary to have something so realistic, but it gives a
    # good idea of the expected format for the returned data structure. This is
    # directly the data structure returned by the whoisit library since it
    # makes a lot of sense.
    #
    # Note, however, that the ToS URL has been shortened and the registration
    # dates are strings instead of datetime objects.
    expected = {
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
    module_mock.domain = mocker.Mock(return_value=expected)

    info = reg.domain_name("example.com")

    assert info == expected
