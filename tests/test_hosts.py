"""Test features related to /etc/hosts."""
from dns_deep_state import hosts
import pytest


hosts_file = """127.0.0.1 localhost

#192.168.10.10 nope ## this line should not match
192.168.10.12 remote remote.domain # this should still match
192.158.10.25 hostname.fqdn"""


@pytest.mark.parametrize("hostname,result",
                         [("hostname.fqdn", True), ("remote", True),
                          ("rem", False), ("nope", False),
                          ("192.158.10.25", False)])
def test_hostname_found(mocker, hostname, result):
    """We're searching for a hostname which is present in the database."""
    m = mocker.patch('builtins.open', mocker.mock_open(read_data=hosts_file))

    h = hosts.HostsProbe()
    present = h.in_database(hostname)

    m.assert_called_once_with("/etc/hosts", "r")
    assert present is result
