from services.dns.lookup import DNSLookup
from services.ssl.checker import SSLChecker
from services.http.status import HTTPChecker
from services.headers.security import SecurityHeadersChecker
from services.cdn.detector import CDNDetector
from services.email.security import EmailSecurityAnalyzer
from services.scoring.health_score import HealthScoreCalculator


class InfrastructureAnalyzer:
    """
    Coordinates all infrastructure analysis services.
    """

    def __init__(self, domain: str):
        self.domain = domain

    def _analyze_dns(self):
        return DNSLookup(self.domain).analyze()

    def _analyze_ssl(self):
        return SSLChecker(self.domain).analyze()

    def _analyze_http(self):
        return HTTPChecker(self.domain).analyze()

    def _analyze_security_headers(self):
        return SecurityHeadersChecker(self.domain).analyze()

    def _analyze_cdn(self):
        return CDNDetector(self.domain).analyze()

    def _analyze_email(self, dns_result):
        """
        Uses existing DNS data.
        No additional DNS lookup is performed.
        """
        return EmailSecurityAnalyzer(
            self.domain,
            dns_result["data"]
        ).analyze()

    def _calculate_health(self, report):
        return HealthScoreCalculator(report).analyze()

    def analyze(self):
        """
        Runs all infrastructure analysis modules.
        """

        dns_result = self._analyze_dns()

        report = {

            "dns": dns_result,

            "ssl": self._analyze_ssl(),

            "http": self._analyze_http(),

            "security_headers": self._analyze_security_headers(),

            "cdn": self._analyze_cdn(),

            "email": self._analyze_email(dns_result)

        }

        report["health"] = self._calculate_health(report)

        return report