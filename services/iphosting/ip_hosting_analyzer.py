import ipaddress
import socket

import requests

from ipwhois import IPWhois

from utils.response import (
    success_response,
    error_response
)


class IPHostingAnalyzer:
    """
    Analyze IP address and hosting information for a domain.

    Information includes:

    • Public IP Address
    • Reverse DNS
    • IPv4 / IPv6
    • ASN
    • Organization
    • CIDR Network
    • ISP
    • Country
    • Region
    • City
    • Hosting Provider
    • Cloud Provider
    """

    def __init__(self, domain: str):

        self.domain = domain

        self.ip_address = None

        self.results = {

            "ip_address": None,

            "hostname": None,

            "reverse_dns": None,

            "ip_version": None,

            "asn": None,

            "organization": None,

            "network": None,

            "isp": None,

            "country": None,

            "region": None,

            "city": None,

            "hosting_provider": None,

            "cloud_provider": None

        }

    # --------------------------------------------------
    # DNS Resolution
    # --------------------------------------------------

    def _resolve_ip(self):
        """
        Resolve domain to public IP.
        """

        self.ip_address = socket.gethostbyname(
            self.domain
        )

        self.results["ip_address"] = self.ip_address

    # --------------------------------------------------
    # Reverse DNS
    # --------------------------------------------------

    def _reverse_dns(self):
        """
        Lookup reverse DNS hostname.
        """

        try:

            hostname, _, _ = socket.gethostbyaddr(
                self.ip_address
            )

            self.results["reverse_dns"] = hostname

            self.results["hostname"] = hostname

        except Exception:

            self.results["reverse_dns"] = "Not Available"

            self.results["hostname"] = self.domain

    # --------------------------------------------------
    # IP Version
    # --------------------------------------------------

    def _detect_ip_version(self):
        """
        Detect IPv4 or IPv6.
        """

        ip = ipaddress.ip_address(
            self.ip_address
        )

        if ip.version == 4:

            self.results["ip_version"] = "IPv4"

        else:

            self.results["ip_version"] = "IPv6"

        # --------------------------------------------------
    # Cloud Provider Detection
    # --------------------------------------------------

    def _detect_cloud_provider(self, organization):
        """
        Detect the underlying cloud provider from the
        organization name.

        Returns a friendly cloud provider name when
        recognized; otherwise returns None.
        """

        if not organization:
            return None

        org = organization.lower()

        cloud_providers = {

            # Amazon Web Services
            "amazon": "Amazon Web Services",
            "amazon technologies": "Amazon Web Services",
            "amazon data services": "Amazon Web Services",
            "amazon-aes": "Amazon Web Services",
            "aws": "Amazon Web Services",

            # Google Cloud
            "google": "Google Cloud",
            "google llc": "Google Cloud",
            "google cloud": "Google Cloud",
            "gcp": "Google Cloud",

            # Microsoft Azure
            "microsoft": "Microsoft Azure",
            "azure": "Microsoft Azure",
            "microsoft corporation": "Microsoft Azure",

            # Oracle
            "oracle": "Oracle Cloud",

            # IBM
            "ibm": "IBM Cloud",

            # Alibaba
            "alibaba": "Alibaba Cloud",

            # Tencent
            "tencent": "Tencent Cloud",

            # Huawei
            "huawei": "Huawei Cloud",

            # OVH
            "ovh": "OVHcloud",

            # DigitalOcean
            "digitalocean": "DigitalOcean",

            # Linode
            "linode": "Linode",

            # Vultr
            "vultr": "Vultr",

            # Hetzner
            "hetzner": "Hetzner",

            # Scaleway
            "scaleway": "Scaleway",

            # Cloudflare
            "cloudflare": "Cloudflare",

            # Akamai
            "akamai": "Akamai",

            # Fastly
            "fastly": "Fastly"

        }

        for keyword, provider in cloud_providers.items():

            if keyword in org:
                return provider

        return None

    # --------------------------------------------------
    # Hosting Provider Detection
    # --------------------------------------------------

    def _detect_hosting_provider(self, organization):
        """
        Normalize common hosting providers.

        Returns a friendly provider name when possible.
        Falls back to the original organization.
        """

        if not organization:
            return None

        org = organization.lower()

        providers = {

            # Amazon
            "amazon": "Amazon Web Services",
            "amazon technologies": "Amazon Web Services",
            "amazon data services": "Amazon Web Services",
            "amazon-aes": "Amazon Web Services",
            "aws": "Amazon Web Services",

            # Google
            "google": "Google Cloud",
            "google llc": "Google Cloud",
            "gcp": "Google Cloud",

            # Microsoft
            "microsoft": "Microsoft Azure",
            "azure": "Microsoft Azure",

            # Cloudflare
            "cloudflare": "Cloudflare",

            # Akamai
            "akamai": "Akamai",

            # Fastly
            "fastly": "Fastly",

            # DigitalOcean
            "digitalocean": "DigitalOcean",

            # Linode
            "linode": "Linode",

            # Vultr
            "vultr": "Vultr",

            # OVH
            "ovh": "OVHcloud",

            # Hetzner
            "hetzner": "Hetzner",

            # Oracle
            "oracle": "Oracle Cloud",

            # IBM
            "ibm": "IBM Cloud",

            # Choopa
            "choopa": "Choopa",

            # Scaleway
            "scaleway": "Scaleway",

            # Hostinger
            "hostinger": "Hostinger",

            # GoDaddy
            "godaddy": "GoDaddy",

            # Bluehost
            "bluehost": "Bluehost",

            # SiteGround
            "siteground": "SiteGround",

            # DreamHost
            "dreamhost": "DreamHost",

            # Namecheap
            "namecheap": "Namecheap",

            # HostGator
            "hostgator": "HostGator"

        }

        for keyword, provider in providers.items():

            if keyword in org:
                return provider

        return organization

        # --------------------------------------------------
    # IPWhois Lookup
    # --------------------------------------------------

    def _lookup_ip_information(self):
        """
        Retrieve ASN, network, organization and
        geographic information using IPWhois.
        """

        lookup = IPWhois(self.ip_address)

        result = lookup.lookup_rdap(depth=1)

        #
        # ASN
        #

        self.results["asn"] = result.get(
            "asn"
        )

        #
        # Network / CIDR
        #

        network = result.get(
            "network",
            {}
        )

        self.results["network"] = network.get(
            "cidr"
        )

        #
        # Organization
        #

        organization = (
            result.get("asn_description")
            or network.get("name")
        )

        self.results["organization"] = organization

        #
        # Hosting Provider
        #

        self.results[
            "hosting_provider"
        ] = self._detect_hosting_provider(
            organization
        )

        #
        # Cloud Provider
        #

        self.results[
            "cloud_provider"
        ] = self._detect_cloud_provider(
            organization
        )

        #
        # ISP
        #

        self.results["isp"] = organization

        #
        # Geographic Information
        #

        objects = result.get(
            "objects",
            {}
        )

        country = None
        region = None
        city = None

        for obj in objects.values():

            contact = obj.get(
                "contact",
                {}
            )

            address = contact.get(
                "address",
                []
            )

            if not address:
                continue

            value = address[0].get(
                "value",
                ""
            )

            if not value:
                continue

            #
            # Split multiline address
            #

            lines = [

                line.strip()

                for line in value.split("\n")

                if line.strip()

            ]

            #
            # Country
            #

            if lines:

                country = lines[-1]

            #
            # Region
            #

            if len(lines) >= 2:

                region = lines[-2]

            #
            # City
            #

            if len(lines) >= 3:

                city = lines[-3]

            #
            # First usable address wins
            #

            break

        self.results["country"] = country

        self.results["region"] = region

        self.results["city"] = city

    # --------------------------------------------------
    # Cleanup
    # --------------------------------------------------

    def _cleanup(self):
        """
        Replace missing values with a consistent
        display value.
        """

        for key, value in self.results.items():

            if value in (

                None,

                "",

                "None"

            ):

                self.results[key] = "Not Available"

        # --------------------------------------------------
    # Analyze
    # --------------------------------------------------

    def analyze(self):
        """
        Execute IP & Hosting analysis.
        """

        try:

            #
            # Resolve Public IP
            #

            self._resolve_ip()

            #
            # Reverse DNS
            #

            self._reverse_dns()

            #
            # IP Version
            #

            self._detect_ip_version()

            #
            # RDAP Lookup
            #

            self._lookup_ip_information()

            #
            # Cleanup
            #

            self._cleanup()

            return success_response(
                self.results
            )

        except socket.gaierror:

            return error_response(
                "Unable to resolve domain name."
            )

        except ValueError:

            return error_response(
                "Invalid IP address."
            )

        except Exception as ex:

            #
            # Partial results are still useful.
            #

            try:

                self._cleanup()

                self.results[
                    "lookup_status"
                ] = "Partial"

                self.results[
                    "lookup_error"
                ] = str(ex)

                return success_response(
                    self.results
                )

            except Exception:

                return error_response(
                    f"IP & Hosting analysis failed: {str(ex)}"
                )