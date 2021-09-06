#!/usr/bin/python3
"""Make a live run with the library with a domain that's working nicely.

Hopefully we can get information from all systems as part of the report for
this test.
"""
import pytest

from dns_deep_state.report import DomainReport


@pytest.mark.integration
def test_live_full_report():
    """Get information from example.com from live systems."""
    dr = DomainReport()

    report = dr.full_report("example.com")

    # Nothing super useful to check for now (but there will be once the
    # structure of the report starts solidifying).
    # The instructions above at least test that we're not getting unexpected
    # errrors while running, and we can see what the report looks like:
    print(report)


if __name__ == '__main__':
    test_live_full_report()
