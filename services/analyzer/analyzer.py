from services.dns.lookup import DNSLookup
from services.ssl.checker import SSLChecker
from services.http.status import HTTPChecker
from services.headers.security import SecurityHeadersChecker
from services.cdn.detector import CDNDetector
from services.email.security import EmailSecurityAnalyzer
from services.whois.analyzer import WhoisAnalyzer
from services.technology.analyzer import TechnologyAnalyzer
from services.iphosting.ip_hosting_analyzer import IPHostingAnalyzer
from services.recommendations.recommendation_engine import RecommendationEngine
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

    def _calculate_health(self, report):
        return HealthScoreCalculator(report).analyze()
    
    def _generate_recommendations(self, report):
        return RecommendationEngine(report).generate()

    def _analyze_technology(self):
        analyzer = TechnologyAnalyzer(self.domain)
        return analyzer.analyze()

    def _analyze_email(self, dns_result):
        """
        Uses existing DNS data.
        No additional DNS lookup is performed.
        """
        return EmailSecurityAnalyzer(
            self.domain,
            dns_result["data"]
        ).analyze()


    def _analyze_ip_hosting(self):
        return IPHostingAnalyzer(self.domain).analyze()

    def _analyze_whois(self):
        return WhoisAnalyzer(self.domain).analyze()

    def analyze(self):
        """
        Runs all infrastructure analysis modules.
        """

        dns_result = self._analyze_dns()

        report = {

            "dns": dns_result,

            "ssl": self._analyze_ssl(),

            "http": self._analyze_http(),

            "technology": self._analyze_technology(),

            "security_headers": self._analyze_security_headers(),

            "cdn": self._analyze_cdn(),

            "email_security": self._analyze_email(dns_result),

            "whois": self._analyze_whois(),

            "ip_hosting": self._analyze_ip_hosting(),

        }

        report["health"] = self._calculate_health(report)

        engine = RecommendationEngine(report)

        report["recommendations"] = engine.generate()

        report["recommendation_summary"] = engine.summary(report["recommendations"])

        return report