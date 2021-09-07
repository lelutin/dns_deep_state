"""Query the DNS about some aspects of a domain."""
from __future__ import annotations

from typing import TYPE_CHECKING

import socket
import dns.exception
import dns.resolver

from dns_deep_state.exceptions import DnsQueryError, DomainError

if TYPE_CHECKING:
    from typing import Optional, Set, List, Dict


class DnsProbe:
    """Starting with an FQDN, inspect DNS state and consistency of configuration.

    In order to have properly functional services, many details in the DNS need
    to be setup properly.  Furthermore, some details that are optional help
    with different aspects of verfications and validation by third parties, so
    we need to take a look at those too.

    .. note:: DNS depends on the domain registration to be in order, so
        Registry checks should happen before we can reach this aspect of the
        infrastructure.
    """

    # This is the AAAA from a.iana-servers.net.
    KNOWN_IPV6_IP = "2001:500:8f::53"

    def __init__(self) -> None:
        """Prepare DNS resolver."""
        self.res = dns.resolver.Resolver()
        if not hasattr(self.res, "resolve"):
            # patch dnspython 1.x library so that we can use this function's
            # new 2.x name. Both the old and new functions use
            # the same parameters.
            # This hack should be removed once debian bullseye is released,
            # since dnspython 1.16 is packaged up to buster.
            self.res.resolve = self.res.query  # type: ignore

        # Without setting this up, queries that don't turn up a result will get
        # stuck for the default timeout of 30 seconds. On the contrary, setting
        # those too low, like 1, can result in useless timeout errors when
        # certain DNS servers take too long to respond.
        self.res.timeout = 3
        self.res.lifetime = 3

        self.ipv6_enabled = self._ipv6_connectivity()

        self._saved_name_servers = None

    def _ipv6_connectivity(self) -> bool:
        """Try to connect to a known IPv6 address to test connectivity.

        :return: True if ipv6 connectivity is possible.
        """
        s = None
        ipv6_supported = False
        if socket.has_ipv6:
            try:
                s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                s.connect((self.KNOWN_IPV6_IP, 53))
                ipv6_supported = True
            except OSError:
                pass

        if s:
            s.close()

        return ipv6_supported

    def canonical_name(self, hostname: str) -> Optional[str]:
        """Given that hostname is a CNAME, resolve its canonical name.

        :param hostname: Hostname for which we're searching a canonical name.

        :return: a string containing the canonical name if found. Otherwise,
            return `None`.

        :raises: See :meth:`lookup`. `NoAnswer` is not raised though.

        .. note::

            If you care about the presence of a CNAME for a hostname, it is
            best to resolve the canonical name first. Looking up the A record
            for a hostname that has a CNAME will automatically be dereferenced
            so it won't tell you if there was a CNAME in the way to getting the
            IP address.
        """
        try:
            response = self.lookup(hostname, "CNAME").canonical_name
        except dns.resolver.NoAnswer:
            # This response from DNS servers means that hostname does not have
            # a CNAME RR, which is not per se an error.
            # It's possible with this response that the subdomain doesn't exist
            # at all. The only way to verify this is by querying for other RR
            # types for the same subdomain.
            response = None

        return response

    def name_servers(self, hostname: str) -> Set[str]:
        """Get all NS entries for hostname.

        This will only return the hostname strings. If you want to then send a
        query directly to one of the nameservers, don't forget that you'll need
        to resolve the hosts to IP addresses.

        :param hostname: Hostname used in query for NS type record.

        :return: A set of strings for all found nameservers.
        """
        response = self.lookup(hostname, "NS").rrset
        return {x.to_text() for x in response}

    def soa(self, hostname: str, name_server: str) -> Dict[str, str]:
        """Get a domain's SOA record.

        For the purposes of this library, when we're requesting an SOA record,
        we want to get it from one specific nameserver. This is because we want
        to check that all servers respond with the same information.

        :param hostname: The domain name for which we're looking up the SOA
            record.

        :param name_server: IP address of the DNS server we're probing for the
            SOA record. The dnspython library is not able to query directly to
            a hostname, so this value needs to be an IP address (v4 or v6).

        :return: A dictionary containing all information from the SOA record.
        """
        response = self.lookup(hostname, "SOA", server=name_server).rrset[0]
        # Unpack to hide library details from callers
        res = {
            "mname": response.mname.to_text(),
            "rname": response.rname.to_text(),
            "serial": response.serial,
            "refresh": response.refresh,
            "retry": response.retry,
            "expire": response.expire,
            "ttl": response.minimum,
        }

        return res

    def v4_address(self, hostname: str) -> List[str]:
        """Get A record for hostname.

        :param hostname: The hostname that we'll lookup for.

        :return: A list of addresses that were found for the A record. If
            nothing is found, the list is empty.
        """
        response = self.lookup(hostname, "A").rrset

        return [x.to_text() for x in response]

    def v6_address(self, hostname: str) -> List[str]:
        """Get AAAA record for hostname.

        :param hostname: The hostname that we,ll lookup for.

        :return: A list of addresses that were found for the AAAA record. If
            nothing is found, the list is empty.
        """
        response = self.lookup(hostname, "AAAA").rrset

        return [x.to_text() for x in response]

    def lookup(self, hostname: str, lookup_type: str,
               server: Optional[str] = None) -> dns.resolver.Answer:
        """Grab DNS RR of type `lookup_type` for `hostname`.

        :param hostname: The hostname for which we're requesting information
            from the DNS.
        :param lookup_type: The type of DNS record that we're requesting.
        :param server: Optional hostname of the DNS server we're sending our
            request towards. This can be used to verify that specific servers
            are responding appropriately.

        :return: whatever response object we got from the dnspython library.
            Wrappers to this method should handle those response objects
            accordingly and hide the library details from their own responses
            by reformatting. This'll make sure that only a limited number of
            methods in this class handle implementation details with regards to
            how DNS entries are looked up.

        :raises dns_deep_state.exceptions.DomainError: received NXDOMAIN,
            meaning that the domain name might not be registered, or the dns
            library can't find NS servers
        :raises dns_deep_state.exceptions.DnsQueryError: recieved YXDOMAIN,
            meaning that the query was malformed (too long), or the query timed
            out
        :raises dns.resolver.NoAnswer: in order for wrapper methods to handle
            this case.
        """
        if server is not None:
            self._set_nameservers([server])

        try:
            response = self.res.resolve(hostname, lookup_type)
        except dns.resolver.NXDOMAIN as err:
            self._reset_nameservers()
            # In the case of CNAME queries, we'll get NXDOMAIN if the domain
            # name is not registered at all. In those cases, there's not much
            # use asking further questions to DNS.
            raise DomainError(err)
        except dns.resolver.NoNameservers as err:
            self._reset_nameservers()
            # Got SERVFAIL, nothing else will resolve for this domain
            raise DomainError(err)
        except dns.resolver.YXDOMAIN as err:
            self._reset_nameservers()
            raise DnsQueryError(err)
        except dns.exception.Timeout as err:
            self._reset_nameservers()
            raise DnsQueryError(err)

        return response

    def _set_nameservers(self, name_servers: List[str]) -> None:
        """Change the nameservers that'll get queried for DNS.

        :param name_servers: List of IP addresses of name servers.
        """
        self._saved_name_servers = self.res.nameservers
        self.res.nameservers = name_servers

    def _reset_nameservers(self) -> None:
        """Set nameservers back to what was previously known, if anything."""
        if self._saved_name_servers is not None:
            self.res.nameservers = self._saved_name_servers
