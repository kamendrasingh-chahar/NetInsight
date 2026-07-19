import time
from http import HTTPStatus

import requests

from utils.response import success_response, error_response


class HTTPChecker:
    """
    Performs HTTP/HTTPS analysis.
    """

    REQUEST_HEADERS = {

        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/138.0.0.0 Safari/537.36"
        )

    }

    def __init__(self, domain: str):

        self.domain = domain

    def _performance_rating(self, response_time: float):
        """
        Returns a performance rating based on response time.
        """

        if response_time < 300:

            return "Excellent"

        elif response_time < 700:

            return "Good"

        elif response_time < 1200:

            return "Average"

        return "Slow"

    def analyze(self):
        """
        Performs HTTP/HTTPS analysis.
        """

        try:

            url = f"https://{self.domain}"

            start = time.perf_counter()

            response = requests.get(
                url,
                headers=self.REQUEST_HEADERS,
                timeout=10,
                allow_redirects=True
            )

            elapsed = round(
                (time.perf_counter() - start) * 1000,
                2
            )

            status_text = HTTPStatus(
                response.status_code
            ).phrase

            performance = self._performance_rating(
                elapsed
            )

            return success_response({

                "status_code": response.status_code,

                "status_text": status_text,

                "https": response.url.startswith("https"),

                "final_url": response.url,

                "redirects": len(response.history),

                "response_time_ms": elapsed,

                "performance": performance,

                "server": response.headers.get(
                    "Server",
                    "Unknown"
                ),

                "content_type": response.headers.get(
                    "Content-Type",
                    "Unknown"
                ),

                "content_length": response.headers.get(
                    "Content-Length",
                    "Unknown"
                ),

                "compression": response.headers.get(
                    "Content-Encoding",
                    "None"
                ),

                "powered_by": response.headers.get(
                    "X-Powered-By",
                    "Not Disclosed"
                )

            })

        except Exception as error:

            return error_response(str(error))