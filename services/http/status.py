import time

import requests

from utils.response import success_response, error_response


class HTTPChecker:
    """
    Performs HTTP/HTTPS analysis.
    """

    def __init__(self, domain: str):
        self.domain = domain

    def analyze(self):

        try:

            url = f"https://{self.domain}"

            start = time.perf_counter()

            response = requests.get(
                url,
                timeout=5,
                allow_redirects=True
            )

            elapsed = round(
                (time.perf_counter() - start) * 1000,
                2
            )

            return success_response({

                "status_code": response.status_code,

                "final_url": response.url,

                "response_time_ms": elapsed,

                "server": response.headers.get(
                    "Server",
                    "Unknown"
                ),

                "https": response.url.startswith("https"),

                "redirects": len(response.history)

            })

        except Exception as error:

            return error_response(str(error))