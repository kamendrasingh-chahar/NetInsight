import re
import dns.resolver


def is_valid_domain(domain: str) -> bool:
    """
    Validates the syntax of a domain name.
    """

    pattern = (
        r"^(?!-)"
        r"(?:[A-Za-z0-9-]{1,63}\.)+"
        r"[A-Za-z]{2,63}$"
    )

    return re.match(pattern, domain) is not None


def domain_exists(domain: str) -> bool:
    """
    Checks whether the domain can be resolved via DNS.
    """

    try:

        dns.resolver.resolve(domain, "A")

        return True

    except Exception:

        try:

            dns.resolver.resolve(domain, "AAAA")

            return True

        except Exception:

            return False