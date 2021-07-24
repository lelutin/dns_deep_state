"""Query domain registries about a domain name."""
import whoisit


class RegistryProbe:
    """Find out how a domain is registered and its status.

    This is the starting point whenever inspecting a domain. If it's not
    registered, there isn't much point in doing any further inspection. But the
    registry has more interesting information like the domain's current status
    and the namesevers known to the registry.

    We will be querying RDAP about the requested domain since it's the system
    that's bound to replace whois. However, there are still many TLDs that have
    not implemented RDAP yet, so we might need to query whois for those and
    we'll want to somehow determine which ones we need to fallback to doing
    this for.
    """

    def __init__(self) -> None:
        """Initialize the registry querying libraries."""
        self.rdap_bootstrap_info = whoisit.bootstrap()

    def domain_name(self, fqdn: str) -> dict:
        """Get information about domain `fqdn` from registry database.

        :param fqdn: The fully qualified domain name that we're querying
            information for.

        :returns: A dictionary containing registration information.
        """
        domain = whoisit.domain(fqdn)

        return domain
