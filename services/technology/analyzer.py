import re
import requests

from bs4 import BeautifulSoup

from utils.response import success_response, error_response


class TechnologyAnalyzer:
    """
    Detect technologies used by a website.

    Detection is based on:

    • HTTP headers
    • HTML meta tags
    • Script sources
    • Link hrefs
    • Framework specific patterns

    The analyzer is intentionally conservative to
    reduce false positives.
    """

    def __init__(self, domain: str):

        self.domain = domain
        self.url = f"https://{domain}"

        self.response = None
        self.headers = {}

        self.html = ""
        self.html_lower = ""

        self.soup = None

        self.script_urls = []
        self.link_urls = []

        self.technologies = {

            "server": "Unknown",

            "powered_by": None,

            "http_version": "Unknown",

            "backend": [],

            "cms": [],

            "frontend": [],

            "compression": [],

            "analytics": []

        }

    # --------------------------------------------------
    # Helpers
    # --------------------------------------------------

    def _add(self, category, value):
        """
        Add unique technology.
        """

        if (
            value
            and value not in self.technologies[category]
        ):

            self.technologies[category].append(value)

    def _contains(self, value):
        """
        Search entire HTML.
        """

        return value.lower() in self.html_lower

    def _script_contains(self, value):
        """
        Search script URLs only.
        """

        value = value.lower()

        return any(
            value in script
            for script in self.script_urls
        )

    def _link_contains(self, value):
        """
        Search stylesheet URLs.
        """

        value = value.lower()

        return any(
            value in link
            for link in self.link_urls
        )

    def _image_contains(self, value):
        """
        Search image URLs.
        """

        value = value.lower()

        return any(
            value in image
            for image in self.image_urls
        )

    # --------------------------------------------------
    # HTML Preparation
    # --------------------------------------------------

    def _prepare_document(self):

        self.headers = self.response.headers

        self.html = self.response.text

        self.html_lower = self.html.lower()

        self.soup = BeautifulSoup(

            self.html,

            "html.parser"

        )

        #
        # Script URLs
        #

        self.script_urls = [

            script.get("src", "").lower()

            for script in self.soup.find_all("script")

            if script.get("src")

        ]

        #
        # Stylesheet URLs
        #

        self.link_urls = [

            link.get("href", "").lower()

         for link in self.soup.find_all("link")

            if link.get("href")

        ]

        #
        # Image URLs
        #

        self.image_urls = [

            img.get("src", "").lower()

            for img in self.soup.find_all("img")

            if img.get("src")

        ]

    # --------------------------------------------------
    # Server Detection
    # --------------------------------------------------

    def _detect_server(self):

        server = self.headers.get(
            "Server",
            ""
        )

        if not server:
            return

        server_lower = server.lower()

        mapping = {

            "cloudflare": "Cloudflare",

            "apache": "Apache",

            "nginx": "Nginx",

            "litespeed": "LiteSpeed",

            "iis": "Microsoft IIS",

            "caddy": "Caddy",

            "openresty": "OpenResty",

            "envoy": "Envoy",

            "vercel": "Vercel",

            "netlify": "Netlify"

        }

        for keyword, name in mapping.items():

            if keyword in server_lower:

                self.technologies["server"] = name

                return

        self.technologies["server"] = server

    # --------------------------------------------------
    # Powered By
    # --------------------------------------------------

    def _detect_powered_by(self):

        powered = self.headers.get(
            "X-Powered-By"
        )

        if powered:

            self.technologies["powered_by"] = powered

        # --------------------------------------------------
    # Backend Detection
    # --------------------------------------------------

    def _detect_backend(self):

        powered = self.headers.get(
            "X-Powered-By",
            ""
        ).lower()

        server = self.headers.get(
            "Server",
            ""
        ).lower()

        #
        # Header Detection
        #

        mapping = {

            "php": "PHP",

            "asp.net": "ASP.NET",

            "asp.net core": "ASP.NET Core",

            "express": "Express.js",

            "node": "Node.js",

            "django": "Django",

            "flask": "Flask",

            "laravel": "Laravel",

            "ruby": "Ruby on Rails",

            "rails": "Ruby on Rails",

            "spring": "Spring Boot",

            "fastapi": "FastAPI"

        }

        for keyword, name in mapping.items():

            if keyword in powered:

                self._add(
                    "backend",
                    name
                )

        #
        # Server Fingerprints
        #

        if "gunicorn" in server:

            self._add(
                "backend",
                "Python"
            )

        if "uwsgi" in server:

            self._add(
                "backend",
                "Python"
            )

        if "tomcat" in server:

            self._add(
                "backend",
                "Java"
            )

            self._add(
                "backend",
                "Spring Boot"
            )

        if "jetty" in server:

            self._add(
                "backend",
                "Java"
            )

        if "kestrel" in server:

            self._add(
                "backend",
                "ASP.NET Core"
            )

        #
        # HTML Fingerprints
        #

        if self._contains("/wp-json/"):

            self._add(
                "backend",
                 "PHP"
            )

        if self._contains("/wp-content/"):

            self._add(
                "backend",
                "PHP"
            )

        if self._contains("laravel"):

            self._add(
                "backend",
                "Laravel"
            )

        if self._contains("django"):

            self._add(
                "backend",
                "Django"
            )

        if self._contains("__next"):

            self._add(
                "backend",
                "Node.js"
            )

        if self._contains("/_next/"):

            self._add(
                "backend",
                "Node.js"
            )

        if self._contains("rails"):

            self._add(
               "backend",
                "Ruby on Rails"
            )

        if self._contains("fastapi"):

            self._add(
                "backend",
                "FastAPI"
            )

    # --------------------------------------------------
    # CMS Detection
    # --------------------------------------------------

    def _detect_cms(self):

        #
        # Generator meta tag
        #

        generator = self.soup.find(

            "meta",

            attrs={
                "name": re.compile(
                    "generator",
                    re.I
                )
            }

        )

        if generator:

            content = generator.get(
                "content",
                ""
            ).strip()

            if content:

                content_lower = content.lower()

                if "wordpress" in content_lower:
                    self._add("cms", "WordPress")

                elif "drupal" in content_lower:
                    self._add("cms", "Drupal")

                elif "joomla" in content_lower:
                    self._add("cms", "Joomla")

                elif "ghost" in content_lower:
                    self._add("cms", "Ghost")

                elif "shopify" in content_lower:
                    self._add("cms", "Shopify")

                elif "wix" in content_lower:
                    self._add("cms", "Wix")

                elif "squarespace" in content_lower:
                    self._add("cms", "Squarespace")

        
        #
        # WordPress
        #

        wordpress_score = 0

        #
        # Strong fingerprints
        #

        if self._contains("/wp-content/"):
            wordpress_score += 3

        if self._contains("/wp-includes/"):
            wordpress_score += 3

        if self._contains("/wp-json/"):
            wordpress_score += 3

        #
        # CSS / JS fingerprints
        #

        if self._script_contains("wp-content"):
            wordpress_score += 2

        if self._script_contains("wp-includes"):
            wordpress_score += 2

        if self._link_contains("wp-content"):
            wordpress_score += 2

        if self._link_contains("wp-includes"):
            wordpress_score += 2

        #
        # Image fingerprints
        #

        if self._image_contains("wp-content"):
            wordpress_score += 2

#
# Common WordPress assets
#

        if self._contains("wp-emoji-release"):
            wordpress_score += 1

        if self._contains("wp-block-library"):
            wordpress_score += 1

        if self._contains("wp-embed"):
            wordpress_score += 1

        if self._contains("xmlrpc.php"):
            wordpress_score += 1

        #
        # Final decision
        #

        if wordpress_score >= 3:

            self._add(
                "cms",
                "WordPress"
            )

    #
    # WordPress almost always runs on PHP
    #

            self._add(
                "backend",
                "PHP"
            )



        #
        # Shopify
        #

        if (

            self._contains("cdn.shopify.com")

            or self._contains("shopify.theme")

            or self._contains("shopify-payment-button")

        ):

            self._add(
                "cms",
                "Shopify"
            )

        #
        # Drupal
        #

        if (

            self._contains("/sites/default/files/")

            or self._contains("drupal-settings-json")

            or self._contains("drupal.js")

        ):

            self._add(
                "cms",
                "Drupal"
            )

        #
        # Joomla
        #

        if (

            self._contains("/media/system/")

            or self._contains("joomla!")

        ):

            self._add(
                "cms",
                "Joomla"
            )

        #
        # Ghost
        #

        if (

            self._contains("/ghost/api/")

            or self._contains("ghost.min.js")

            or self._contains("ghost-sdk")

        ):

            self._add(
                "cms",
                "Ghost"
            )

        #
        # Wix
        #

        if (

            self._contains("static.wixstatic.com")

            or self._contains("_wixcidx")

            or self._contains("wix-image")

        ):

            self._add(
                "cms",
                "Wix"
            )

        #
        # Squarespace
        #

        if (

            self._contains("static.squarespace.com")

            or self._contains("squarespace-cdn")

        ):

            self._add(
                "cms",
                "Squarespace"
            )

        # --------------------------------------------------
    # Frontend Detection
    # --------------------------------------------------

    def _detect_frontend(self):

        #
        # Bootstrap
        #

        if (

            self._link_contains("bootstrap")

            or self._script_contains("bootstrap")

            or self._contains("bootstrap.bundle.min.js")

            or self._contains("bootstrap.min.css")

        ):

            self._add(
                "frontend",
                "Bootstrap"
            )

        #
        # Tailwind CSS
        #

        if (

            self._link_contains("tailwind")

            or self._contains("tailwindcss")

            or self._contains("tailwind.min.css")

            or self._contains("__TAILWIND_CONFIG__")

        ):

            self._add(
                "frontend",
                "Tailwind CSS"
            )

        #
        # jQuery
        #

        if (

            self._script_contains("jquery")

            or self._contains("jquery.min.js")

            or self._contains("jquery.js")

        ):

            self._add(
                "frontend",
                "jQuery"
            )

        #
        # React
        #

        react_detected = (

            self._contains("react-dom")

            or self._contains("react.production.min.js")

            or self._contains("react.development.js")

            or self._contains("data-reactroot")

            or self._contains("__reactdevtools")

            or self._contains("__reactfiber")

        )

        if react_detected:

            self._add(
                "frontend",
                "React"
            )

        #
        # Next.js
        #

        next_detected = (

            self._contains("/_next/")

            or self._contains("__next")

            or self._script_contains("/_next/")

        )

        if next_detected:

            self._add(
                "frontend",
                "Next.js"
            )

            #
            # Next.js implies React
            #

            self._add(
                "frontend",
                "React"
            )

        #
        # Vue.js
        #

        if (

            self._contains("__vue__")

            or self._contains("vue.runtime")

            or self._contains("vue.global")

            or self._script_contains("vue")

        ):

            self._add(
                "frontend",
                "Vue.js"
            )

        #
        # Nuxt.js
        #

        if (

            self._contains("/_nuxt/")

            or self._contains("__nuxt")

            or self._script_contains("/_nuxt/")

        ):

            self._add(
                "frontend",
                "Nuxt.js"
            )

            #
            # Nuxt implies Vue
            #

            self._add(
                "frontend",
                "Vue.js"
            )

        #
        # Angular
        #

        if (

            self._contains("ng-version")

            or self._contains("ng-app")

            or self._contains("angular.min.js")

            or self._script_contains("angular")

        ):

            self._add(
                "frontend",
                "Angular"
            )

        #
        # Svelte
        #

        if (

            self._contains("__SVELTE")

            or self._contains("svelte")

            or self._script_contains("svelte")
        ):

            self._add(
                "frontend",
                "Svelte"
            )


        #
        # Alpine.js
        #

        if (

            self._contains("x-data")

            or self._contains("x-show")

            or self._contains("alpinejs")

            or self._script_contains("alpine")
        ):

            self._add(
                "frontend",
                "Alpine.js"
            )

        #
        #Material UI
        #

        if (

            self._contains("mui-")

            or self._contains("@mui")

            or self._contains("material-ui")

        ):

            self._add(
                "frontend",
                "Material UI"
            )

        #
        # Bulma
        #

        if (

            self._link_contains("bulma")

            or self._contains("bulma.min.css")

        ):

            self._add(
                "frontend",
                "Bulma"
            )

        #
        # Foundation
        #

        if (

            self._link_contains("foundation")

            or self._contains("foundation.min.css")

        ):

            self._add(
                "frontend",
                "Foundation"
            )

        #
        # Semantic UI
        #

        if (

            self._contains("semantic.min.css")

            or self._contains("semantic.min.js")

            or self._script_contains("semantic")

        ):

            self._add(
                "frontend",
                "Semantic UI"
            )

        #
        # Emotion
        #

        if (

            self._contains("emotion-cache")

            or self._contains("@emotion")

        ):

            self._add(
                "frontend",
                "Emotion"
            )

        #
        # Styled Components
        #

        if (

            self._contains("styled-components")

            or self._contains("data-styled")

        ):

            self._add(
                "frontend",
                "Styled Components"
            )

    # --------------------------------------------------
    # Analytics Detection
    # --------------------------------------------------

    def _detect_analytics(self):

        #
        # Google Analytics
        #

        if (

            self._contains("www.google-analytics.com")

            or self._contains("google-analytics.com")

            or self._contains("gtag(")

            or self._contains("ga(")

        ):

            self._add(
                "analytics",
                "Google Analytics"
            )

        #
        # Google Tag Manager
        #

        if (

            self._contains("googletagmanager.com")

            or self._contains("gtm.js")

        ):

            self._add(
                "analytics",
                "Google Tag Manager"
            )

        #
        # Microsoft Clarity
        #

        if (

            self._contains("clarity.ms")

            or self._contains("clarity.js")

        ):

            self._add(
                "analytics",
                "Microsoft Clarity"
            )

        #
        # Hotjar
        #

        if (

            self._contains("hotjar")

            or self._contains("static.hotjar.com")

        ):

            self._add(
                "analytics",
                "Hotjar"
            )

        #
        # Facebook Pixel
        #

        if (

            self._contains("connect.facebook.net")

            or self._contains("fbq(")

        ):

            self._add(
                "analytics",
                "Facebook Pixel"
            )

        # --------------------------------------------------
    # Compression Detection
    # --------------------------------------------------

    def _detect_compression(self):

        encoding = self.headers.get(
            "Content-Encoding",
            ""
        ).lower()

        if "br" in encoding:

            self._add(
                "compression",
                "Brotli"
            )

        if "gzip" in encoding:

            self._add(
                "compression",
                "Gzip"
            )

        if "deflate" in encoding:

            self._add(
                "compression",
                "Deflate"
            )

    # --------------------------------------------------
    # HTTP Version Detection
    # --------------------------------------------------

    def _detect_http_version(self):

        version_map = {

            9: "HTTP/0.9",

            10: "HTTP/1.0",

            11: "HTTP/1.1",

            20: "HTTP/2"

        }

        try:

            raw_version = getattr(
                self.response.raw,
                "version",
                None
            )

            self.technologies["http_version"] = version_map.get(
                raw_version,
                "Unknown"
            )

        except Exception:

            self.technologies["http_version"] = "Unknown"

    # --------------------------------------------------
    # Cleanup
    # --------------------------------------------------

    def _cleanup(self):

        for key in self.technologies:

            value = self.technologies[key]

            #
            # Remove duplicates
            #

            if isinstance(value, list):

                self.technologies[key] = sorted(
                    list(
                        set(value)
                    )
                )

        #
        # Normalize Powered By
        #

        if not self.technologies["powered_by"]:

            self.technologies["powered_by"] = "Not Exposed"

    # --------------------------------------------------
    # Analyze
    # --------------------------------------------------

    def analyze(self):

        try:

            self.response = requests.get(

                self.url,

                timeout=10,

                allow_redirects=True,

                headers={

                    "User-Agent": (
                        "NetInsight Technology Scanner"
                    )

                }

            )

            self._prepare_document()

            #
            # Detection Pipeline
            #

            self._detect_server()

            self._detect_powered_by()

            self._detect_backend()

            self._detect_cms()

            self._detect_frontend()

            self._detect_analytics()

            self._detect_compression()

            self._detect_http_version()

            self._cleanup()

            return success_response(
                self.technologies
            )

        except requests.exceptions.Timeout:

            return error_response(
                "Technology detection timed out."
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
                f"Technology detection failed: {str(ex)}"
            )