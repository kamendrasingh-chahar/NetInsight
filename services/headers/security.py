import requests

from utils.response import success_response, error_response


class SecurityHeadersChecker:
    """
    Analyzes important HTTP security headers.
    """

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "description": "Forces HTTPS connections"
        },
        "Content-Security-Policy": {
            "description": "Protects against XSS attacks"
        },
        "X-Frame-Options": {
            "description": "Protects against clickjacking"
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME type sniffing"
        },
        "Referrer-Policy": {
            "description": "Controls referrer information"
        },
        "Permissions-Policy": {
            "description": "Restricts browser features"
        }
    }

    REQUEST_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/138.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,"
            "application/xml;q=0.9,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close"
    }

    def __init__(self, domain: str):
        self.domain = domain

    def analyze(self):
        """
        Retrieves and analyzes HTTP security headers.
        """

        try:

            response = requests.get(
                f"https://{self.domain}",
                headers=self.REQUEST_HEADERS,
                timeout=10,
                allow_redirects=True
            )

            results = {}

            for header, metadata in self.SECURITY_HEADERS.items():

                value = response.headers.get(header)

                results[header] = {

                    "present": value is not None,

                    "value": value if value else "Missing",

                    "description": metadata["description"],

                    "severity": (
                        "good"
                        if value
                        else "critical"
                    )

                }

            return success_response({

                "final_url": response.url,

                "status_code": response.status_code,

                "headers": results

            })

        except Exception as error:

            return error_response(str(error))