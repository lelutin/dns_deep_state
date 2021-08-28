"""Perform some verifications on the local hosts database."""
import re


class HostsProbe:
    """Test for presence of a hostname inside the local hosts file.

    The presence of a hostname inside this file might drastically change the
    behavior of a service that you're trying to use on a certain hostname, so
    it's important to check whether you have such an override in place.

    :method: in_database()

    :param database_path: Absolute path to the local hosts database file.
    """

    def __init__(self, database_path: str = "/etc/hosts") -> None:
        """Prepare all relevant drivers for queries."""
        self.database_path = database_path

        self._hosts_cache = []
        with open(self.database_path, 'r') as hosts:
            for line in hosts.readlines():
                self._hosts_cache.append(line)

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
