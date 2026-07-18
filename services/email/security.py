import dns.resolver

from utils.response import success_response


class EmailSecurityAnalyzer:
    """
    Performs email security analysis.
    """

    COMMON_DKIM_SELECTORS = [

        "selector1",

        "selector2",

        "default",

        "google",

        "smtp",

        "mail",

        "dkim",

        "k1",

    ]

    EMAIL_PROVIDERS = {

        "google.com": "Google Workspace",

        "googlemail.com": "Google Workspace",

        "protection.outlook.com": "Microsoft 365",

        "amazonses.com": "Amazon SES",

        "zoho.com": "Zoho Mail",

        "protonmail.ch": "Proton Mail",

        "proton.me": "Proton Mail",

        "messagingengine.com": "Fastmail",

        "mx.cloudflare.net": "Cloudflare Email Routing"

    }

    def __init__(self, domain, dns_records):
        """
        Initializes the email security analyzer.
        """

        self.domain = domain
        self.dns = dns_records

    def _has_mx(self):
        """
        Checks whether MX records exist.
        """

        return len(self.dns.get("MX", [])) > 0

    def _has_spf(self):
        """
        Checks whether an SPF record exists.
        """

        txt_records = self.dns.get("TXT", [])

        for record in txt_records:

            record = record.lower().strip('"')

            if "v=spf1" in record:

                return True

        return False

    def _has_dmarc(self):
        """
        Checks whether a DMARC record exists.
        """

        try:

            answers = dns.resolver.resolve(
                f"_dmarc.{self.domain}",
                "TXT"
            )

            for record in answers:

                text = str(record).strip('"').lower()

                if text.startswith("v=dmarc1"):

                    return True

        except Exception:
            pass

        return False

    def _check_dkim(self):
        """
        Attempts to locate a DKIM record using common selectors.
        """

        for selector in self.COMMON_DKIM_SELECTORS:

            try:

                answers = dns.resolver.resolve(
                    f"{selector}._domainkey.{self.domain}",
                    "TXT"
                )

                for record in answers:

                    text = str(record).strip('"').lower()

                    if "v=dkim1" in text or "k=rsa" in text:

                        return {

                            "enabled": True,

                            "selector": selector

                        }

            except Exception:
                continue

        return {

            "enabled": False,

            "selector": "Unknown"

        }

    def _detect_provider(self):
        """
        Detects the email provider using MX records first,
        then SPF records as a fallback.
        """

        # ------------------------------
        # 1. Check MX Records
        # ------------------------------

        mx_records = self.dns.get("MX", [])

        for mx in mx_records:

            record = mx.lower()

            for pattern, provider in self.EMAIL_PROVIDERS.items():

                if pattern in record:

                    return {

                        "name": provider,

                        "detected_via": "MX"

                    }

        # ------------------------------
        # 2. Check SPF Record
        # ------------------------------

        txt_records = self.dns.get("TXT", [])

        for txt in txt_records:

            record = txt.lower().strip('"')

            if "_spf.google.com" in record:

                return {

                    "name": "Google Workspace",

                    "detected_via": "SPF"

                }

            if "spf.protection.outlook.com" in record:

                return {

                    "name": "Microsoft 365",

                    "detected_via": "SPF"

                }

            if "amazonses.com" in record:

                return {

                    "name": "Amazon SES",

                    "detected_via": "SPF"

                }

            if "zoho.com" in record:

                return {

                    "name": "Zoho Mail",

                    "detected_via": "SPF"

                }

            if "protonmail.ch" in record or "proton.me" in record:

                return {

                    "name": "Proton Mail",

                    "detected_via": "SPF"

                }

            if "messagingengine.com" in record:

                return {

                    "name": "Fastmail",

                    "detected_via": "SPF"

                }

        # ------------------------------
        # 3. Unknown
        # ------------------------------

        return {

            "name": "Unknown",

            "detected_via": "None"

        }

    def analyze(self):
        """
        Runs all email security checks.
        """

        return success_response({

            "mx": self._has_mx(),

            "spf": self._has_spf(),

            "dmarc": self._has_dmarc(),

            "dkim": self._check_dkim(),

            "provider": self._detect_provider()

        })