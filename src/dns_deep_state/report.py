"""Gather information about a domain name and produce a report about it.

Rough early specs:

    Output of the report should be in JSON.

    Input should be a domain name (maybe some additional sub-domains?)

    There should be a binary that uses the library and formats the report to
    screen

    There should be some configuration format that lets you mark whether
    reported hosts are known to be something and whether it's problematic to
    the user or not. maybe only for the binary? It should be possible for users
    to specify an alternative configuration file.

"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from dns.resolver import NoAnswer
from publicsuffix2 import PublicSuffixList

from dns_deep_state.dns import DnsProbe
from dns_deep_state.hosts import HostsProbe
from dns_deep_state.registry import RegistryProbe
from dns_deep_state.exceptions import DomainError

if TYPE_CHECKING:
    from typing import Set, Dict, Union


class DomainReport:
    """Inspect the state of a domain name and report on possible issues."""

    def __init__(self) -> None:
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

        This method inspects data returned from all probes and also
        adds errors for the following correlations:
            the domain name uses one of the known public suffixes
                if not, fail early
            the DNS servers in the zone match the ones in the registry
            check reported resolved hosts for presence in local hosts database
        """
        # TODO decide exactly what structure the report should take
        report = {}

        domain_name = self.psl.get_sld(fqdn, strict=True)
        if domain_name is None:
            raise ValueError(
                f"{fqdn} is not using a known public suffix or TLD")
        report["domain"] = domain_name

        report["registry"] = self.registry_report(fqdn)
        report["dns"] = self.dns_report(fqdn)
        # TODO extract portion of report with resolved hosts and give that to
        # the next report method instead of fqdn
        hostnames: Set[str] = set()
        report["hosts"] = self.local_hosts_report(hostnames)

        return json.dumps(report)

    def registry_report(self, domain_name: str) -> dict:
        """Run a full inspection and produce a report about what was found.

        The registry should be checked for:
            domain is registered
            not expired
            not in a problematic status
            the DNS hosts in the registry have glue records

        :param domain_name: The domain name for which we'll be gathering
          information into a report.

        :return: A dictionary containing report information.
        """
        info = self.reg.domain_name(domain_name)
        report = {}
        report["status"] = info["status"]
        report["expiration_date"] = str(info["expiration_date"])
        report["registrar"] = info["entities"]["registrar"][0]["name"]
        report["nameservers"] = info["nameservers"]
        return report

    def dns_report(self, fqdn: str) -> dict:
        """Run all DNS inspections and produce report as a dictionary.

        To produce a full report we want to inspect the following details about
        a domain name:
            * List out NS entries
            * Grab the SOA and report the serial
              * Get the SOA from all NS entries and compare the serials. If
                there is a mismatch, add an error in the report about a
                mismatch in the SOA and which nameservers disagree
              * If any of the NS servers fail to respond, add an error about
                each one that failed
                * If no NS server responded, raise an exception to fail early
            * Details about email setup
              * MX is present. all values have a PTR corresponding to the same
                hostname
                * check all hosts in the same way as resolving tests down below
                  and add results to report
              * SPF is present
              * DKIM is present (we'll need a configuration option for a set of
                DKIM sub-domains to search for)
              * DMARC is present
              * MTA-STS is present
              * onionmx SRV field exists
              * SRV records exist for IMAP/POP3
              * autodiscover/autoconfig TXT entries exist
            * general security fields
              * DNSSEC: DS and DNSKEY
              * CAA
            * Resolve a series of hosts
              * check for CNAME first and report if any is found
              * A and AAAA, also check for PTR on found values
              * always check if there are NS entries for subdomains and report
                the delegations that were found
              * at least:
                * NS servers
                * top of domain
                * www subdomain
                * hosts found in SRV records
              * it would be a good idea to have a parameter for extra hosts to
                include in the report

        :param fqdn: The domain name for which we'll gather DNS information
          into a report.

        :return: A dictionary containing report information.
        """
        report = {}

        try:
            nameservers = self.dns.name_servers(fqdn)
        except (DomainError, NoAnswer):
            raise DomainError(
                f"No nameserver was found for {fqdn}. Cannot go further.")

        ns_data = []
        for ns in nameservers:
            ns_ips = self.dns.v4_address(ns)
            if self.dns.ipv6_enabled:
                ns_ips.extend(self.dns.v6_address(ns))

            for ns_ip in ns_ips:
                ns_struct: Dict[str, Union[str, Dict[str, str]]] = {
                    "hostname": ns,
                    "ip_address": ns_ip,
                }
                # TODO catch errors from this
                soa = self.dns.soa(fqdn, ns_ip)

                ns_struct["soa"] = soa

                ns_data.append(ns_struct)

        report["nameservers"] = ns_data

        return report

    def local_hosts_report(self, hosts: Set[str]) -> dict:
        """Produce a report about the presence of hosts in the local database.

        Host names will not be verified for validity, only whether or not they
        are in the local hosts database.

        :param hosts: Set of unique host names

        :return: A dictionary with host names as keys and a boolean as values
          to indicate if the corresponding host name was found in the local
          database.
        """
        report = {}
        for h in hosts:
            report[h] = self.hosts.in_database(h)
        return report
