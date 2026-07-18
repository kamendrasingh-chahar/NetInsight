from utils.response import success_response, error_response

import socket
import ssl
from datetime import datetime


class SSLChecker:
    """
    Retrieves SSL certificate information.
    """

    def __init__(self, domain: str):
        self.domain = domain

    def _get_field(self, certificate_field, field_name):
        """
        Extracts a value from a nested SSL certificate field.
        """

        for item in certificate_field:
            for key, value in item:
                if key == field_name:
                    return value

        return "Unknown"

    def analyze(self):
        """
        Performs SSL certificate analysis.
        """

        try:

            context = ssl.create_default_context()

            with socket.create_connection(
                (self.domain, 443),
                timeout=5
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=self.domain
                ) as secure_socket:

                    cert = secure_socket.getpeercert()

            issued_to = self._get_field(
                cert["subject"],
                "commonName"
            )

            issued_by = self._get_field(
                cert["issuer"],
                "organizationName"
            )

            valid_from = datetime.strptime(
                cert["notBefore"],
                "%b %d %H:%M:%S %Y %Z"
            )

            valid_until = datetime.strptime(
                cert["notAfter"],
                "%b %d %H:%M:%S %Y %Z"
            )

            days_remaining = (valid_until - datetime.utcnow()).days

            return success_response({

                "issued_to": issued_to,

                "issued_by": issued_by,

                "valid_from": valid_from.strftime("%d %b %Y"),

                "valid_until": valid_until.strftime("%d %b %Y"),

                "days_remaining": days_remaining,

            })

        except Exception as error:

            return error_response(str(error))