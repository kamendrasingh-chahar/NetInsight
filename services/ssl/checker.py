import socket
import ssl

from datetime import datetime

from utils.response import success_response, error_response


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

                    certificate = secure_socket.getpeercert()

                    tls_version = secure_socket.version()

                    cipher_suite = secure_socket.cipher()[0]

            issued_to = self._get_field(
                certificate["subject"],
                "commonName"
            )

            issued_by = self._get_field(
                certificate["issuer"],
                "organizationName"
            )

            valid_from = datetime.strptime(
                certificate["notBefore"],
                "%b %d %H:%M:%S %Y %Z"
            )

            valid_until = datetime.strptime(
                certificate["notAfter"],
                "%b %d %H:%M:%S %Y %Z"
            )

            days_remaining = (
                valid_until - datetime.utcnow()
            ).days

            return success_response({

                "valid": True,

                "expired": days_remaining < 0,

                "issued_to": issued_to,

                "issued_by": issued_by,

                "valid_from": valid_from.strftime("%d %b %Y"),

                "valid_until": valid_until.strftime("%d %b %Y"),

                "days_remaining": days_remaining,

                "tls_version": tls_version,

                "cipher": cipher_suite

            })

        except Exception as error:

            return error_response(str(error))