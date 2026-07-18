import re


def is_valid_domain(domain: str) -> bool:
    """
    Validates a domain name.
    """

    pattern = (
        r"^(?!-)"
        r"(?:[A-Za-z0-9-]{1,63}\.)+"
        r"[A-Za-z]{2,63}$"
    )

    return re.match(pattern, domain) is not None