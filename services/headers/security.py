import requests

from utils.response import success_response, error_response


class SecurityHeadersChecker:
    """
    Analyzes important HTTP security headers.
    """

    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    def __init__(self, domain: str):
        self.domain = domain

    def analyze(self):

        try:

            response = requests.get(
                f"https://{self.domain}",
                timeout=5
            )

            headers = {}

            for header in self.SECURITY_HEADERS:

                headers[header] = response.headers.get(
                    header,
                    "Missing"
                )

            return success_response(headers)

        except Exception as error:

            return error_response(str(error))