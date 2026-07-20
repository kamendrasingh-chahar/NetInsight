from concurrent.futures import ThreadPoolExecutor
import time

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

    def _timed(self, name, func, *args):
        """
        Executes an analyzer and prints how long it took.
        """
        start = time.perf_counter()

        result = func(*args)

        elapsed = time.perf_counter() - start

        print(f"{name:<22}: {elapsed:.2f}s")

        return result

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

    def _analyze_technology(self):
        return TechnologyAnalyzer(self.domain).analyze()

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

    def _calculate_health(self, report):
        return HealthScoreCalculator(report).analyze()

    def analyze(self):
        """
        Runs all infrastructure analysis modules.
        """

        total_start = time.perf_counter()

        # DNS first
        dns_result = self._timed(
            "DNS",
            self._analyze_dns
        )

        # Run remaining analyzers in parallel
        with ThreadPoolExecutor() as executor:

            ssl_future = executor.submit(
                self._timed,
                "SSL",
                self._analyze_ssl
            )

            http_future = executor.submit(
                self._timed,
                "HTTP",
                self._analyze_http
            )

            technology_future = executor.submit(
                self._timed,
                "Technology",
                self._analyze_technology
            )

            headers_future = executor.submit(
                self._timed,
                "Security Headers",
                self._analyze_security_headers
            )

            cdn_future = executor.submit(
                self._timed,
                "CDN",
                self._analyze_cdn
            )

            whois_future = executor.submit(
                self._timed,
                "WHOIS",
                self._analyze_whois
            )

            hosting_future = executor.submit(
                self._timed,
                "IP Hosting",
                self._analyze_ip_hosting
            )

            email_future = executor.submit(
                self._timed,
                "Email Security",
                self._analyze_email,
                dns_result
            )

            report = {
                "dns": dns_result,
                "ssl": ssl_future.result(),
                "http": http_future.result(),
                "technology": technology_future.result(),
                "security_headers": headers_future.result(),
                "cdn": cdn_future.result(),
                "email_security": email_future.result(),
                "whois": whois_future.result(),
                "ip_hosting": hosting_future.result(),
            }

        health_start = time.perf_counter()

        report["health"] = self._calculate_health(report)

        print(
            f"{'Health Score':<22}: "
            f"{time.perf_counter() - health_start:.2f}s"
        )

        recommendation_start = time.perf_counter()

        engine = RecommendationEngine(report)

        report["recommendations"] = engine.generate()

        report["recommendation_summary"] = engine.summary(
            report["recommendations"]
        )

        print(
            f"{'Recommendations':<22}: "
            f"{time.perf_counter() - recommendation_start:.2f}s"
        )

        print("-" * 40)
        print(
            f"{'TOTAL SCAN TIME':<22}: "
            f"{time.perf_counter() - total_start:.2f}s"
        )
        print("-" * 40)

        return report