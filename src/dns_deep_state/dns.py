"""Query the DNS about some aspects of a domain."""
import dns.exception
import dns.resolver

from dns_deep_state.exceptions import DnsQueryError, DomainError
from publicsuffix2 import PublicSuffixList


class Dns:
    """Starting with an FQDN, inspect DNS state and consistency of configuration.

    DNS depends on the domain registration to be in order, so Registry checks
    should happen before we can reach this aspect of the infrastructure.

    This is the main point where complexity expands. In order to have properly
    functional services, many details in the DNS need to be setup properly.
    Furthermore, some details that are optional help with different aspects of
    verfications and validation by third parties, so we need to take a look at
    those too.
    """

    def __init__(self, fqdn):
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

        psl = PublicSuffixList()
        self.domain_name = psl.get_sld(fqdn, strict=True)
        if self.domain_name is None:
            raise DomainError("{} is not using a known public suffix or TLD".format(fqdn))

    def canonical_name(self, hostname):
        """Given that hostname is a CNAME, resolve its canonical name.

        Returns a string containing the canonical name if found. Otherwise,
        returns None.

        Raises the same exceptions as lookup(), except for NoAnswer.

        If you care about the presence of a CNAME for a hostname, it is best to
        resolve the canonical name first. Looking up the A record for a
        hostname that has a CNAME will automatically be dereferenced so it
        won't tell you if there was a CNAME in the way to getting the IP
        address.
        """
        try:
            response = self.lookup(hostname, "CNAME").canonical_name
        except dns.resolver.NoAnswer:
            # This response from DNS servers means that hostname does not have
            # a CNAME RR, which is not per se an error.
            # It's possible with this response that the subdomain doesn't exist
            # at all. The only way to verify this is by querying for other RR types
            # for the same subdomain.
            response = None

        return response

    def lookup(self, hostname, lookup_type):
        """Grab DNS RR of type `lookup_type` for `hostname`.

        Returns whatever response object we got from the dnspython library.
        Wrappers to this method should handle those response objects
        accordingly and hide the library details from their own responses by
        reformatting. This'll make sure that only a limited number of methods
        in this class handle implementation details with regards to how DNS
        entries are looked up.

        Raises `dns_deep_state.exceptions.DomainError` in cases where:
          * we receive NXDOMAIN, meaning that the domain name might not be registered
          * the dns library can't find NS servers
        Raises `dns_deep_state.exceptions.DnsQueryError` in cases where:
          * we recieve YXDOMAIN, meaning that the query was malformed (too long)
          * the query timed out

        Lets `dns.resolver.NoAnswer move higher up in order for wrapper methods
        to handle this case.
        """
        try:
            response = self.res.resolve(hostname, lookup_type)
        except dns.resolver.NXDOMAIN as err:
            # In the case of CNAME queries, we'll get NXDOMAIN if the domain
            # name is not registered at all. In those cases, there's not much
            # use asking further questions to DNS.
            raise DomainError(err)
        except dns.resolver.NoNameservers as err:
            # Got SERVFAIL, nothing else will resolve for this domain
            raise DomainError(err)
        except dns.resolver.YXDOMAIN as err:
            raise DnsQueryError(err)
        except dns.exception.Timeout as err:
            raise DnsQueryError(err)

        return response
