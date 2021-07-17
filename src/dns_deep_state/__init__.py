"""Gather information about a domain name and produce a report about it.

Rough early specs:

    Output of the report should be in JSON.

    Input should be a domain name (maybe some additional sub-domains?)

    There should be a binary that uses the library and formats the report to screen

    There should be some configuration format that lets you mark whether
    reported hosts are known to be something and whether it's problematic to
    the user or not. maybe only for the binary? It should be possible for users
    to specify an alternative configuration file.

"""
import json

from dns_deep_state.dns import DnsProbe
from dns_deep_state.hosts import HostsProbe
from dns_deep_state.registry import RegistryProbe
from publicsuffix2 import PublicSuffixList

class dns_deep_state:
    """Gather information from multiple involved systems and produce a report."""

    def __init__(self):
        """Initialise information probes."""
        self.psl = PublicSuffixList()
        self.reg = RegistryProbe()
        self.dns = DnsProbe()
        self.hosts = HostsProbe()

    def full_report(self, fqdn: str) -> str:
        """Grab information about `fqdn` and produce a report about it.

        :param fqdn: The fully qualified domain name for which a report is
            produced.

        :raises ValueError: If `fqdn` is not using a known public suffix.
            Indeed, we'll be prodding some public services for information
            about the domain, so it doesn't make much sense to run the
            information gathering for a domain name that won't have any valid
            information on those services.

        :return: a JSON-serialized data structure

        .. note::
            If `fqdn` is not a second-level domain (e.g. the name that would be
            registered with a registry, the report will be run on the
            second-level domain part of it instead.

        This report should inspect grab reports from all elements and also
        test:
            the domain name uses one of the known public suffixes
                if not, fail early
            the DNS servers in the zone match the ones in the registry
                if not, add an error in the report about this
            local hosts database
                check reported resolved hosts for presence in local hosts database
        """
        #TODO decide exactly what structure the report should take
        report = {}

        domain_name = self.psl.get_sld(fqdn, strict=True)
        if domain_name is None:
            raise ValueError("{} is not using a known public suffix or TLD".format(fqdn))
        report["domain"] = domain_name
        
        report["registry"] = self.reg.full_report(fqdn)
        report["dns"] = self.dns.full_report(fqdn)
        # TODO extract portion of report with resolved hosts and give that to
        # the next report method instead of fqdn
        hostnames = set([])
        report["hosts"] = self.hosts.full_report(hostnames)

        return json.dumps(report)
