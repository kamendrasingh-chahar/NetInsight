import requests
import dns.resolver

from utils.response import success_response, error_response


class CDNDetector:
    """
    Detects whether a website is using a CDN.
    """

    HTTP_PATTERNS = {

        "Cloudflare": [
            "cf-ray",
            "cf-cache-status"
        ],

        "CloudFront": [
            "x-amz-cf-id"
        ],

        "Fastly": [
            "x-served-by"
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

        "CacheFly": [
            "cachefly.net"
        ]
    }

    def __init__(self, domain: str):
        self.domain = domain

    def _check_http_headers(self):
        """
        Detect CDN using HTTP response headers.
        """

        evidence = []

        response = requests.get(
            f"https://{self.domain}",
            timeout=5,
            allow_redirects=True
        )

        headers = {
            key.lower(): value.lower()
            for key, value in response.headers.items()
        }

        for provider, patterns in self.HTTP_PATTERNS.items():

            for pattern in patterns:

                for header, value in headers.items():

                    if pattern in header or pattern in value:

                        evidence.append(
                            f"{provider} detected via HTTP header '{header}'"
                        )

                        return provider, evidence

        return None, evidence

    def _check_dns(self):
        """
        Detect CDN using DNS CNAME records.
        """

        evidence = []

        try:

            answers = dns.resolver.resolve(
                self.domain,
                "CNAME"
            )

            cname = str(answers[0].target).lower()

            for provider, patterns in self.DNS_PATTERNS.items():

                for pattern in patterns:

                    if pattern in cname:

                        evidence.append(
                            f"{provider} detected via DNS CNAME '{cname}'"
                        )

                        return provider, evidence

        except Exception:
            pass

        return None, evidence

    def analyze(self):

        try:

            http_provider, http_evidence = self._check_http_headers()

            dns_provider, dns_evidence = self._check_dns()

            evidence = http_evidence + dns_evidence

            provider = http_provider or dns_provider

            if http_provider and dns_provider:

                confidence = "High"

            elif http_provider or dns_provider:

                confidence = "Medium"

            else:

                confidence = "Low"

            return success_response({

                "detected": provider is not None,

                "provider": provider if provider else "Unknown",

                "confidence": confidence,

                "evidence": evidence

            })

        except Exception as error:

            return error_response(str(error))