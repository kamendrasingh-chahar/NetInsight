import requests

from bs4 import BeautifulSoup

from utils.response import success_response, error_response


class WebPageFetcher:
    """
    Fetches and parses a webpage once so multiple analyzers
    can reuse the same response, headers and HTML.

    Returns:
        {
            "response": requests.Response,
            "headers": dict,
            "html": str,
            "soup": BeautifulSoup,
            "script_urls": [],
            "link_urls": [],
            "image_urls": []
        }
    """

    USER_AGENT = "NetInsight WebPage Fetcher"

    def __init__(self, domain: str):

        self.domain = domain
        self.url = f"https://{domain}"

    def fetch(self):

        try:

            response = requests.get(

                self.url,

                timeout=10,

                allow_redirects=True,

                headers={
                    "User-Agent": self.USER_AGENT
                }

            )

            soup = BeautifulSoup(

                response.text,

                "html.parser"

            )

            script_urls = [

                script.get("src", "").lower()

                for script in soup.find_all("script")

                if script.get("src")

            ]

            link_urls = [

                link.get("href", "").lower()

                for link in soup.find_all("link")

                if link.get("href")

            ]

            image_urls = [

                image.get("src", "").lower()

                for image in soup.find_all("img")

                if image.get("src")

            ]

            return success_response({

                "response": response,

                "headers": response.headers,

                "html": response.text,

                "html_lower": response.text.lower(),

                "soup": soup,

                "script_urls": script_urls,

                "link_urls": link_urls,

                "image_urls": image_urls

            })

        except requests.exceptions.Timeout:

            return error_response(
                "Website request timed out."
            )

        except requests.exceptions.ConnectionError:

            return error_response(
                "Unable to connect to the target website."
            )

        except requests.exceptions.SSLError:

            return error_response(
                "SSL handshake failed."
            )

        except Exception as ex:

            return error_response(
                f"Unable to fetch webpage: {str(ex)}"
            )