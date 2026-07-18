from utils.response import success_response

import dns.resolver


class DNSLookup:
    """
    Handles DNS lookups for a domain.
    """

    def __init__(self, domain: str):
        self.domain = domain

    def _resolve(self, record_type: str):
        """
        Generic DNS resolver.
        Returns a list of DNS records.
        """

        try:
            answers = dns.resolver.resolve(self.domain, record_type)
            return [str(record) for record in answers]

        except Exception:
            return []

    def get_a_records(self):
        """Returns IPv4 (A) records."""
        return self._resolve("A")

    def get_aaaa_records(self):
        """Returns IPv6 (AAAA) records."""
        return self._resolve("AAAA")

    def get_mx_records(self):
        """Returns Mail Exchange (MX) records."""
        return self._resolve("MX")

    def get_ns_records(self):
        """Returns Name Server (NS) records."""
        return self._resolve("NS")

    def get_txt_records(self):
        """Returns TXT records."""
        return self._resolve("TXT")

    def get_cname_records(self):
        """Returns Canonical Name (CNAME) records."""
        return self._resolve("CNAME")

    def get_soa_records(self):
        """Returns Start of Authority (SOA) records."""
        return self._resolve("SOA")

    def analyze(self):
        """
        Performs a complete DNS analysis.
        """

        records = {
            "A": self.get_a_records(),
            "AAAA": self.get_aaaa_records(),
            "MX": self.get_mx_records(),
            "NS": self.get_ns_records(),
            "TXT": self.get_txt_records(),
            "CNAME": self.get_cname_records(),
            "SOA": self.get_soa_records(),
        }

        return success_response(records)