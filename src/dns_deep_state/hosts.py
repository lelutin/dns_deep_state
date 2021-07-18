"""Perform some verifications on the local hosts database."""
import re

from typing import Set


class HostsProbe:
    """Test for presence of a hostname inside the local hosts file.

    The presence of a hostname inside this file might drastically change the
    behavior of a service that you're trying to use on a certain hostname, so
    it's important to check whether you have such an override in place.

    :method: in_database()
    :method: full_report(hosts)
    """

    def __init__(self, database_path: str = "/etc/hosts") -> None:
        """Prepare all relevant drivers for queries.

        :param database_path: absolute path to the local hosts database file.
        """
        self.database_path = database_path

        self._hosts_cache = []
        with open(self.database_path, 'r') as hosts:
            for line in hosts.readlines():
                self._hosts_cache.append(line)

    def full_report(self, hosts: Set[str]) -> dict:
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
            report[h] = self.in_database(h)
        return report

    def in_database(self, hostname: str) -> bool:
        """Check whether a hostname is present in the local hosts database.

        :param hostname: A hostname that we'll lookup in the hosts database.

        :return: True if hostname is in hosts database, False otherwise.
        """
        for line in self._hosts_cache:
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
