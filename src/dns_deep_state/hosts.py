"""Perform some verifications on the local hosts database."""
import re


class Hosts:
    """Test for presence of a hostname inside the local hosts file.

    This file is usually found in /etc/hosts in unix/linux systems.

    The presence of a hostname inside this file might drastically change the
    behavior of a service that you're trying to use on a certain hostname, so
    it's important to check whether you have such an override in place.
    """

    def __init__(self, hosts_database: str = "/etc/hosts") -> None:
        """Prepare all relevant drivers for queries."""
        self.hosts_database = hosts_database

    def in_database(self, hostname: str) -> bool:
        """Check whether a hostname is present in the local hosts database."""
        with open(self.hosts_database, 'r') as hosts:
            for line in hosts.readlines():
                # remove trailing newline char
                line = re.sub(r'\n$', '', line)
                # chop off comments
                line = re.sub(r' *#.*$', '', line)
                # empty up lines that have only spaces or tabs; they're not
                # interesting to process
                line = re.sub(r'^[ \t]+$', '', line)
                # discard empty lines
                if not line:
                    continue

                host_aliases = line.split()[1:]

                if hostname in host_aliases:
                    return True

        return False
