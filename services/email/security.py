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

    def _get_mx_records(self):
        """
        Returns all MX records.
        """

        records = []

        for mx in self.dns.get("MX", []):

            try:

                parts = mx.split(maxsplit=1)

                if len(parts) == 2:

                    records.append({

                        "priority": int(parts[0]),

                        "exchange": parts[1]

                    })

                else:

                    records.append({

                        "priority": "-",

                        "exchange": mx

                    })

            except Exception:

                    records.append({

                        "priority": "-",

                        "exchange": mx

                    })

            return records

    def _get_spf_record(self):
        """
        Returns the SPF record.
        """

        txt_records = self.dns.get("TXT", [])

        for record in txt_records:

            record = record.strip('"')

            if record.lower().startswith("v=spf1"):

                return record

        return None

    def _get_dmarc_record(self):
        """
        Returns the DMARC record.
        """

        try:

            answers = dns.resolver.resolve(

                f"_dmarc.{self.domain}",

                "TXT"

            )

            for record in answers:

                text = str(record).strip('"')

                if text.lower().startswith("v=dmarc1"):

                    return text

        except Exception:

            pass

        return None

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
        mx_records = self._get_mx_records()

        spf_record = self._get_spf_record()

        dmarc_record = self._get_dmarc_record()

        return success_response({

            "mx": mx_records,

            "spf": spf_record,

            "dmarc": dmarc_record,

            "dkim": self._check_dkim(),

            "provider": self._detect_provider()

        })