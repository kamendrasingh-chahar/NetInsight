import requests
import dns.resolver

from collections import defaultdict

from services.common.webpage_fetcher import WebPageFetcher

from utils.response import success_response, error_response


class CDNDetector:
    """
    Detects whether a website is using a Content Delivery Network (CDN)
    using HTTP response headers, Server header, and DNS records.
    """

    HTTP_PATTERNS = {

        "Cloudflare": [
            "cf-ray",
            "cf-cache-status",
            "server: cloudflare"
        ],

        "CloudFront": [
            "x-amz-cf-id",
            "x-amz-cf-pop"
        ],

        "Fastly": [
            "x-served-by",
            "fastly-debug"
        ],

        "Akamai": [
            "akamai",
            "akamai-grn",
            "x-akamai"
        ],

        "Azure Front Door": [
            "x-azure-ref"
        ],

        "Google": [
            "alt-svc",
            "server: gws",
            "server: google frontend"
        ],

        "Imperva": [
            "x-iinfo",
            "x-cdn"
        ],

        "Sucuri": [
            "x-sucuri-id",
            "x-sucuri-cache"
        ],

        "BunnyCDN": [
            "cdn-pull",
            "bunnycdn"
        ],

        "KeyCDN": [
            "x-edge-location"
        ]
    }

    DNS_PATTERNS = {

        "Cloudflare": [
            "cloudflare.net"
        ],

        "CloudFront": [
            "cloudfront.net"
        ],

        "Fastly": [
            "fastly.net"
        ],

        "Akamai": [
            "akamaiedge.net",
            "edgesuite.net",
            "edgekey.net"
        ],

        "Azure CDN": [
            "azureedge.net"
        ],

        "Azure Front Door": [
            "afd.azureedge.net"
        ],

        "CacheFly": [
            "cachefly.net"
        ],

        "StackPath": [
            "stackpathdns.com"
        ],

        "KeyCDN": [
            "kxcdn.com"
        ],

        "BunnyCDN": [
            "b-cdn.net"
        ],

        "G-Core": [
            "gcorelabs.net"
        ],

        "Imperva": [
            "incapdns.net"
        ]
    }

    def __init__(self, domain: str):
        self.domain = domain

    def _add_detection(
        self,
        scores,
        evidence,
        methods,
        provider,
        method,
        detail,
        weight
    ):
        """
        Adds weighted evidence for a CDN provider.
        """

        scores[provider] += weight

        methods[provider].add(method)

        evidence[provider].append(detail)

    def _calculate_confidence(self, score: int):

        if score >= 6:
            return "High"

        if score >= 3:
            return "Medium"

        return "Low"

    def _check_http_headers(self):

        scores = defaultdict(int)
        evidence = defaultdict(list)
        methods = defaultdict(set)

        try:

            page = WebPageFetcher(self.domain).fetch()

            if not page["success"]:
                return scores, methods, evidence

            response = page["data"]["response"]

            headers = {
                key.lower(): value.lower()
                for key, value in response.headers.items()
            }

            server = headers.get("server", "").lower()

            for provider, patterns in self.HTTP_PATTERNS.items():

                for pattern in patterns:

                    # Match header names
                    for header in headers.keys():

                        if pattern == header:

                            self._add_detection(
                                scores,
                                evidence,
                                methods,
                                provider,
                                "HTTP Header",
                                header,
                                3
                            )

                    # Match header values
                    for header, value in headers.items():

                        if pattern in value:

                            self._add_detection(
                                scores,
                                evidence,
                                methods,
                                provider,
                                "HTTP Header",
                                f"{header}: {value}",
                                2
                            )

                    # Explicit Server header check
                    if pattern.startswith("server:"):

                        expected = pattern.replace("server:", "").strip()

                        if expected in server:

                            self._add_detection(
                                scores,
                                evidence,
                                methods,
                                provider,
                                "Server Header",
                                server,
                                3
                            )

        except Exception:
            pass

        return scores, methods, evidence

    def _check_dns(self):

        scores = defaultdict(int)
        evidence = defaultdict(list)
        methods = defaultdict(set)

        # -----------------------------
        # Check CNAME
        # -----------------------------

        try:

            answers = dns.resolver.resolve(
                self.domain,
                "CNAME"
            )

            cname = str(
                answers[0].target
            ).lower()

            for provider, patterns in self.DNS_PATTERNS.items():

                for pattern in patterns:

                    if pattern in cname:

                        self._add_detection(
                            scores,
                            evidence,
                            methods,
                            provider,
                            "DNS CNAME",
                            cname,
                            3
                        )

        except Exception:
            pass

        # -----------------------------
        # Check A Records
        # -----------------------------

        try:

            answers = dns.resolver.resolve(
                self.domain,
                "A"
            )

            for record in answers:

                ip = str(record)

                evidence["IP Address"].append(ip)

        except Exception:
            pass

        # -----------------------------
        # Check AAAA Records
        # -----------------------------

        try:

            answers = dns.resolver.resolve(
                self.domain,
                "AAAA"
            )

            for record in answers:

                ip = str(record)

                evidence["IPv6"].append(ip)

        except Exception:
            pass

        return scores, methods, evidence

    def analyze(self):

        http_scores, http_methods, http_evidence = self._check_http_headers()

        dns_scores, dns_methods, dns_evidence = self._check_dns()

        # -----------------------------
        # Merge Results
        # -----------------------------

        providers = set(
            list(http_scores.keys()) +
            list(dns_scores.keys())
        )

        final_scores = {}

        final_methods = {}

        final_evidence = {}

        for provider in providers:

            final_scores[provider] = (
                http_scores.get(provider, 0)
                +
                dns_scores.get(provider, 0)
            )

            final_methods[provider] = list(
                http_methods.get(provider, set())
                |
                dns_methods.get(provider, set())
            )

            final_evidence[provider] = (
                http_evidence.get(provider, [])
                +
                dns_evidence.get(provider, [])
            )

        # -----------------------------
        # No CDN Detected
        # -----------------------------

        if not final_scores:

            return success_response({

                "detected": False,

                "provider": "Unknown",

                "confidence": "Low",

                "detected_via": [],

                "evidence": []

            })

        # -----------------------------
        # Highest Score Wins
        # -----------------------------

        provider = max(
            final_scores,
            key=final_scores.get
        )

        score = final_scores[provider]

        confidence = self._calculate_confidence(score)

        return success_response({

            "detected": True,

            "provider": provider,

            "confidence": confidence,

            "detected_via": final_methods[provider],

            "evidence": final_evidence[provider]

        })

