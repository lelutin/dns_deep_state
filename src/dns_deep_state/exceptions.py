"""Exceptions used by the dns_state library."""


class DomainError(Exception):
    """The domain name does not exist."""


class DnsQueryError(Exception):
    """The DNS query failed."""
