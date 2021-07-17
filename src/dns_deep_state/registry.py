"""Query domain registries about a domain name."""


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

    def full_report(self, domain_name: str) -> dict:
        """Run a full inspection and produce a report about what was found.

        The registry should be checked for:
            domain is registered
            not expired
            not in a problematic status
            the DNS hosts in the registry have glue records
        """
        return {}
