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
from publicsuffix2 import PublicSuffixList

class dns_deep_state:
    """The report should inspect:
        the domain name uses one of the known public suffixes
        the registry
            domain is registered
            not expired or in another problematic status
            the DNS hosts in the registry have glue records
        the dns
            the DNS servers in the zone correspond to the ones in the registry
            all DNS servers return the same serial for SOA
            details about email setup
                MX is present. all IPs have a PTR that correspond to the MX host
                SPF is present
                DKIM is present (we might need a configuration option for a set of DKIM sub-domains to search for
                DMARC is present
                MTA-STS is present
                onionmx field exists
                SRV records exist for IMAP/POP3
                autodiscover/autoconfig TXT entries exist
            general security fields
                DNSSEC: DS and DNSKEY
                CAA
        check some hosts
            in the local hosts database
            A/AAAA and PTR
            top-level, www., all hosts found in previous checks, additionally configured sub-domains?
    """

    def __init__(self):
        """Initialise information probes."""
        self.psl = PublicSuffixList()
        self.dns = DnsProbe()
        self.hosts = HostsProbe()

    def full_report(self, fqdn: str):
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

        """
        #TODO decide exactly what structure the report should take
        report = {}

        domain_name = self.psl.get_sld(fqdn, strict=True)
        if domain_name is None:
            raise ValueError("{} is not using a known public suffix or TLD".format(fqdn))
        report["domain"] = domain_name
        
        #report["registry"] = self.registry.full_report(fqdn)
        report["dns"] = json.loads(self.dns.full_report(fqdn))
        # TODO still not sure about this part, we might want to inspect a
        # number of hosts on dns too...
        report["hosts"] = json.loads(self.hosts.full_report(fqdn))

        return json.dumps(report)
