#!/usr/bin/python3
"""Try to resolve a domain that does not resolve.

We'll expect a certain exception in this case.
"""
import pytest

from dns_deep_state.report import DomainReport
from dns_deep_state.exceptions import DomainError


@pytest.mark.integration
def test_domain_unknown_tld():
    """Get report for domain with unknown TLD."""
    dr = DomainReport()

    with pytest.raises(ValueError):
        dr.full_report("something.invalid")


@pytest.mark.integration
def test_domain_no_resolve():
    """Get information from domain that is guaranteed not to resolve."""
    dr = DomainReport()

    with pytest.raises(DomainError):
        dr.full_report("hopefullythisdomainwillneverexist.com")
