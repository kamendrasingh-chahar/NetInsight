from datetime import datetime, timezone
import re
import pycountry
import whois

from utils.response import success_response, error_response


class WhoisAnalyzer:
    """
    Performs WHOIS lookup for a domain.
    """

    def __init__(self, domain: str):
        self.domain = domain

    def _normalize_date(self, value):
        """
        Normalizes WHOIS date values.
        WHOIS libraries may return lists or timezone-aware datetimes.
        """

        if not value:
            return None

        if isinstance(value, (list, tuple)):
            value = value[0]

        if not isinstance(value, datetime):
            return None

        # Convert timezone-aware datetime to naive UTC
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)

        return value

    def _format_date(self, value):
        """
        Formats datetime objects.
        """

        if not value:
            return "Unavailable"

        try:
            return value.strftime("%d %b %Y")
        except Exception:
            return str(value)

    def _get_country_name(self, country):
        """
        Converts ISO country codes (e.g. US, CA, IN)
        to full country names.
        """

        if not country:
            return "Unavailable"

        if isinstance(country, (list, tuple)):
            country = country[0]

        country = str(country).strip()

        lookup = pycountry.countries.get(alpha_2=country.upper())

        if lookup:
            return lookup.name

        return country

    def _calculate_domain_age(self, creation_date):
        """
        Calculates domain age.
        """

        if not creation_date:
            return "Unavailable"

        days = (datetime.utcnow() - creation_date).days
        years = days // 365

        return f"{years} Year" if years == 1 else f"{years} Years"

    def _days_until_expiry(self, expiry_date):
        """
        Calculates remaining days until expiry.
        """

        if not expiry_date:
            return None

        return (expiry_date - datetime.utcnow()).days

    def _clean_status(self, status):
        """
        Cleans WHOIS status values by removing URLs,
        parentheses and duplicates.
        """

        if not status:
            return []

        if isinstance(status, str):
            status = [status]

        elif isinstance(status, (tuple, set)):
            status = list(status)

        cleaned = set()

        for item in status:

            item = str(item)

            # Remove ICANN URLs
            item = re.sub(r"https?://\S+", "", item)

            # Remove everything after "("
            item = item.split("(")[0]

            # Normalize whitespace
            item = " ".join(item.split()).strip()

            if item:
                cleaned.add(item)

        return sorted(cleaned)

    def _normalize_name_servers(self, name_servers):
        """
        Normalizes name servers.
        """

        if not name_servers:
            return []

        if isinstance(name_servers, set):
            name_servers = list(name_servers)

        if not isinstance(name_servers, (list, tuple)):
            name_servers = [name_servers]

        return sorted(
            str(ns).upper()
            for ns in name_servers
        )

    def analyze(self):
        """
        Performs WHOIS lookup.
        """

        try:

            result = whois.whois(self.domain)

            creation_date = self._normalize_date(
                result.creation_date
            )

            updated_date = self._normalize_date(
                result.updated_date
            )

            expiration_date = self._normalize_date(
                result.expiration_date
            )

            domain_name = result.domain_name

            if isinstance(domain_name, (list, tuple)):
                domain_name = domain_name[0]

            registrar = result.registrar

            if isinstance(registrar, (list, tuple)):
                registrar = registrar[0]

            data = {

                "domain_name": (
                    str(domain_name).lower()
                    if domain_name
                    else "Unavailable"
                ),

                "registrar": registrar or "Unavailable",

                "creation_date": self._format_date(
                    creation_date
                ),

                "updated_date": self._format_date(
                    updated_date
                ),

                "expiration_date": self._format_date(
                    expiration_date
                ),

                "domain_age": self._calculate_domain_age(
                    creation_date
                ),

                "expires_in": self._days_until_expiry(
                    expiration_date
                ),

                "status": self._clean_status(
                    result.status
                ),

                "name_servers": self._normalize_name_servers(
                    result.name_servers
                ),

                "registrant_country": self._get_country_name(
                    getattr(result, "country", None)
                )
            }

            return success_response(data)

        except Exception as ex:

            return error_response(
                f"WHOIS lookup failed: {str(ex)}"
            )