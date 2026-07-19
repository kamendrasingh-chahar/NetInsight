"""
Recommendation Rules

Contains all recommendation rule sets.

Each method analyzes one section of the infrastructure report
and returns a list of Recommendation objects.
"""

from services.recommendations.recommendation import Recommendation


class RecommendationRules:
    """
    Collection of recommendation rule sets.
    """

    # ==========================================================
    # SSL
    # ==========================================================

    @staticmethod
    def ssl(report):
        """
        SSL recommendation rules.
        """

        recommendations = []

        ssl = report.get("ssl", {})

        # ------------------------------------------------------
        # SSL Analysis Failed
        # ------------------------------------------------------

        if not ssl.get("success", False):

            recommendations.append(
                Recommendation(
                    severity="Critical",
                    category="SSL",
                    issue="SSL certificate could not be validated.",
                    recommendation="Install and correctly configure a valid SSL certificate.",
                    impact="Users may receive browser security warnings and encrypted communication will not be available."
                )
            )

            return recommendations

        data = ssl.get("data", {})

        # ------------------------------------------------------
        # Invalid Certificate
        # ------------------------------------------------------

        if not data.get("valid", False):

            recommendations.append(
                Recommendation(
                    severity="Critical",
                    category="SSL",
                    issue="SSL certificate is invalid.",
                    recommendation="Replace the invalid SSL certificate with a trusted certificate.",
                    impact="Browsers may block access to the website."
                )
            )

        # ------------------------------------------------------
        # Expired Certificate
        # ------------------------------------------------------

        elif data.get("expired", False):

            recommendations.append(
                Recommendation(
                    severity="Critical",
                    category="SSL",
                    issue="SSL certificate has expired.",
                    recommendation="Renew the SSL certificate immediately.",
                    impact="Users will see browser security warnings."
                )
            )

        # ------------------------------------------------------
        # Certificate Expiration
        # ------------------------------------------------------

        days = data.get("days_remaining")

        if days is not None:

            if days <= 30:

                recommendations.append(
                    Recommendation(
                        severity="High",
                        category="SSL",
                        issue="SSL certificate expires soon.",
                        recommendation=f"Renew the SSL certificate within the next {days} days.",
                        impact="Failure to renew may cause service disruption."
                    )
                )

            elif days <= 90:

                recommendations.append(
                    Recommendation(
                        severity="Medium",
                        category="SSL",
                        issue="SSL certificate should be renewed soon.",
                        recommendation=f"Plan certificate renewal within the next {days} days.",
                        impact="Early renewal prevents unexpected expiration."
                    )
                )

        # ------------------------------------------------------
        # TLS Version
        # ------------------------------------------------------

        tls = data.get("tls_version", "")

        if tls in ("TLSv1", "TLSv1.0", "TLSv1.1"):

            recommendations.append(
                Recommendation(
                    severity="High",
                    category="SSL",
                    issue=f"{tls} is outdated.",
                    recommendation="Disable TLS 1.0/1.1 and enable TLS 1.2 or TLS 1.3.",
                    impact="Older TLS versions contain known security vulnerabilities."
                )
            )

        return recommendations

    # ==========================================================
    # Security Headers
    # ==========================================================

    @staticmethod
    def headers(report):
        """
        Security Header recommendation rules.
        """

        recommendations = []

        headers_result = report.get("security_headers", {})

        # Header analysis failed
        if not headers_result.get("success", False):
            return recommendations

        headers = headers_result.get("data", {}).get("headers", {})

        header_rules = {
            "Content-Security-Policy": {
                "severity": "High",
                "issue": "Content Security Policy (CSP) header is missing.",
                "recommendation": (
                    "Configure a Content-Security-Policy (CSP) header to help "
                    "protect against Cross-Site Scripting (XSS) attacks."
                ),
                "impact": (
                    "Without CSP, malicious JavaScript has a greater chance of "
                    "executing in users' browsers."
                )
            },

            "Strict-Transport-Security": {
                "severity": "High",
                "issue": "Strict-Transport-Security (HSTS) header is missing.",
                "recommendation": (
                    "Enable HSTS to ensure browsers always connect using HTTPS."
                ),
                "impact": (
                    "Users may be vulnerable to SSL stripping attacks."
                )
            },

            "X-Frame-Options": {
                "severity": "Medium",
                "issue": "X-Frame-Options header is missing.",
                "recommendation": (
                    "Configure X-Frame-Options to prevent clickjacking attacks."
                ),
                "impact": (
                    "Attackers could embed your website inside malicious pages."
                )
            },

            "X-Content-Type-Options": {
                "severity": "Medium",
                "issue": "X-Content-Type-Options header is missing.",
                "recommendation": (
                    "Set X-Content-Type-Options to 'nosniff'."
                ),
                "impact": (
                    "Browsers may incorrectly interpret file types, increasing "
                    "security risks."
                )
            },

            "Referrer-Policy": {
                "severity": "Low",
                "issue": "Referrer-Policy header is missing.",
                "recommendation": (
                    "Configure a Referrer-Policy header to control how much "
                    "referral information is shared."
                ),
                "impact": (
                    "Sensitive URL information may be exposed to third-party websites."
                )
            },

            "Permissions-Policy": {
                "severity": "Low",
                "issue": "Permissions-Policy header is missing.",
                "recommendation": (
                    "Configure a Permissions-Policy header to restrict "
                    "unnecessary browser features."
                ),
                "impact": (
                    "Restricting browser capabilities reduces the application's "
                    "attack surface."
                )
            }
        }

        for header_name, rule in header_rules.items():

            header = headers.get(header_name)

            if header and not header.get("present", False):

                recommendations.append(
                    Recommendation(
                        severity=rule["severity"],
                        category="Security Headers",
                        issue=rule["issue"],
                        recommendation=rule["recommendation"],
                        impact=rule["impact"]
                    )
                )

        return recommendations

    # ==========================================================
    # HTTP
    # ==========================================================

    @staticmethod
    def http(report):
        """
        HTTP recommendation rules.
        """

        recommendations = []

        http_result = report.get("http", {})

        # HTTP analysis failed
        if not http_result.get("success", False):

            recommendations.append(
                Recommendation(
                    severity="High",
                    category="HTTP",
                    issue="HTTP analysis could not be completed.",
                    recommendation="Verify that the website is reachable and responding correctly.",
                    impact="Website availability and performance cannot be assessed."
                )
            )

            return recommendations

        data = http_result.get("data", {})

        # ------------------------------------------------------
        # HTTPS
        # ------------------------------------------------------

        if not data.get("https", False):

            recommendations.append(
                Recommendation(
                    severity="Critical",
                    category="HTTP",
                    issue="HTTPS is not enabled.",
                    recommendation="Enable HTTPS and redirect all HTTP traffic to HTTPS.",
                    impact="Data transmitted between users and the website may be intercepted."
                )
            )

        # ------------------------------------------------------
        # HTTP Status Code
        # ------------------------------------------------------

        status = data.get("status_code", 0)

        if status >= 500:

            recommendations.append(
                Recommendation(
                    severity="High",
                    category="HTTP",
                    issue=f"Website returned HTTP {status}.",
                    recommendation="Investigate server-side errors and restore normal service.",
                    impact="Visitors may be unable to access the website."
                )
            )

        elif status >= 400:

            recommendations.append(
                Recommendation(
                    severity="High",
                    category="HTTP",
                    issue=f"Website returned HTTP {status}.",
                    recommendation="Resolve client-side errors or missing resources.",
                    impact="Users may experience broken pages or unavailable content."
                )
            )

        # ------------------------------------------------------
        # Response Time
        # ------------------------------------------------------

        response_time = data.get("response_time_ms", 0)

        if response_time >= 2000:

            recommendations.append(
                Recommendation(
                    severity="High",
                    category="Performance",
                    issue="Website response time is very slow.",
                    recommendation="Investigate server performance, database queries, and caching.",
                    impact="Slow websites reduce user experience and may affect search rankings."
                )
            )

        elif response_time >= 1000:

            recommendations.append(
                Recommendation(
                    severity="Medium",
                    category="Performance",
                    issue="Website response time is slower than recommended.",
                    recommendation="Optimize server response time and enable caching where possible.",
                    impact="Page load times may negatively affect user experience."
                )
            )

        # ------------------------------------------------------
        # Compression
        # ------------------------------------------------------

        compression = data.get("compression", "").lower()

        if compression in ("none", "", "unknown"):

            recommendations.append(
                Recommendation(
                    severity="Low",
                    category="Performance",
                    issue="HTTP compression is not enabled.",
                    recommendation="Enable Gzip or Brotli compression for web responses.",
                    impact="Pages may require more bandwidth and load more slowly."
                )
            )

        return recommendations

    # ==========================================================
    # DNS
    # ==========================================================

    @staticmethod
    def dns(report):
        """
        DNS recommendation rules.
        """

        recommendations = []

        dns_result = report.get("dns", {})

        # ------------------------------------------------------
        # DNS lookup failed
        # ------------------------------------------------------

        if not dns_result.get("success", False):

            recommendations.append(
                Recommendation(
                    severity="Critical",
                    category="DNS",
                    issue="DNS lookup failed.",
                    recommendation="Verify that the domain exists and DNS is configured correctly.",
                    impact="Clients may be unable to locate or access the website."
                )
            )

            return recommendations

        data = dns_result.get("data", {})

        # ------------------------------------------------------
        # A Records
        # ------------------------------------------------------

        if not data.get("A"):

            recommendations.append(
                Recommendation(
                    severity="Critical",
                    category="DNS",
                    issue="No A records were found.",
                    recommendation="Configure at least one IPv4 A record.",
                    impact="The domain may not resolve for IPv4 clients."
                )
            )

        # ------------------------------------------------------
        # AAAA Records
        # ------------------------------------------------------

        if not data.get("AAAA"):

            recommendations.append(
                Recommendation(
                    severity="Low",
                    category="DNS",
                    issue="No IPv6 (AAAA) records were found.",
                    recommendation="Consider enabling IPv6 by publishing AAAA records.",
                    impact="IPv6-only users may experience reduced connectivity."
                )
            )

        # ------------------------------------------------------
        # MX Records
        # ------------------------------------------------------

        if not data.get("MX"):

            recommendations.append(
                Recommendation(
                    severity="High",
                    category="DNS",
                    issue="No MX records were found.",
                    recommendation="Configure MX records if the domain should receive email.",
                    impact="Email sent to this domain may not be delivered."
                )
            )

        # ------------------------------------------------------
        # NS Records
        # ------------------------------------------------------

        if not data.get("NS"):

            recommendations.append(
                Recommendation(
                    severity="High",
                    category="DNS",
                    issue="No authoritative name servers were found.",
                    recommendation="Configure authoritative NS records for the domain.",
                    impact="DNS resolution may become unreliable."
                )
            )

        # ------------------------------------------------------
        # SOA Record
        # ------------------------------------------------------

        if not data.get("SOA"):

            recommendations.append(
                Recommendation(
                    severity="Medium",
                    category="DNS",
                    issue="SOA record is missing.",
                    recommendation="Publish a valid Start of Authority (SOA) record.",
                    impact="DNS zone management and synchronization may not function correctly."
                )
            )

        # ------------------------------------------------------
        # TXT Records
        # ------------------------------------------------------

        if not data.get("TXT"):

            recommendations.append(
                Recommendation(
                    severity="Low",
                    category="DNS",
                    issue="No TXT records were found.",
                    recommendation="Consider adding TXT records for SPF, domain verification, or other services.",
                    impact="Email authentication and third-party service verification may be limited."
                )
            )

        return recommendations

    # ==========================================================
    # Email Security
    # ==========================================================

    @staticmethod
    def email(report):
        """
        Email Security recommendation rules.
        """

        recommendations = []

        email_result = report.get("email_security", {})

        if not email_result.get("success", False):

            recommendations.append(
                Recommendation(
                    severity="High",
                    category="Email Security",
                    issue="Email security configuration could not be analyzed.",
                    recommendation="Verify DNS configuration and email authentication records.",
                    impact="Email security posture cannot be assessed."
                )
            )

            return recommendations

        data = email_result.get("data", {})

        # ==========================================================
        # MX Records
        # ==========================================================

        if not data.get("mx", False):

            recommendations.append(
                Recommendation(
                    severity="High",
                    category="Email Security",
                    issue="No MX records were found.",
                    recommendation="Configure MX records if your domain is intended to receive email.",
                    impact="The domain will not be able to receive email messages."
                )
            )

        # ------------------------------------------------------
        # SPF
        # ------------------------------------------------------

        if not data.get("spf", False):

            recommendations.append(
                Recommendation(
                    severity="High",
                    category="Email Security",
                    issue="SPF record is missing.",
                    recommendation="Publish an SPF record to specify authorized mail servers.",
                    impact="Attackers may spoof your domain when sending emails."
                )
            )

        # ------------------------------------------------------
        # DKIM
        # ------------------------------------------------------

        dkim = data.get("dkim", {})

        enabled = dkim.get("enabled")

        if enabled is False:

            recommendations.append(
                Recommendation(
                    severity="Medium",
                    category="Email Security",
                    issue="DKIM signing is not configured.",
                    recommendation="Enable DKIM signing for outgoing email.",
                    impact="Recipients cannot verify that emails were not modified in transit."
                )
            )

        # ------------------------------------------------------
        # DMARC
        # ------------------------------------------------------

        if not data.get("dmarc", False):

            recommendations.append(
                Recommendation(
                    severity="High",
                    category="Email Security",
                    issue="DMARC policy is missing.",
                    recommendation="Publish a DMARC policy to protect against email spoofing and phishing.",
                    impact="Attackers may impersonate your domain in phishing campaigns."
                )
            )

        return recommendations

    # ==========================================================
    # IP Hosting
    # ==========================================================

    @staticmethod
    def hosting(report):
        """
        IP Hosting recommendation rules.
        """

        recommendations = []

        hosting_result = report.get("ip_hosting", {})

        # ------------------------------------------------------
        # Analysis Failed
        # ------------------------------------------------------

        if not hosting_result.get("success", False):

            recommendations.append(
                Recommendation(
                    severity="Medium",
                    category="IP Hosting",
                    issue="IP hosting information could not be determined.",
                    recommendation="Verify DNS resolution and ensure the server is publicly accessible.",
                    impact="Hosting infrastructure cannot be fully assessed."
                )
            )

            return recommendations

        data = hosting_result.get("data", {})

        # ------------------------------------------------------
        # Hosting Provider
        # ------------------------------------------------------

        provider = data.get("hosting_provider")

        if not provider or provider == "Unknown":

            recommendations.append(
                Recommendation(
                    severity="Low",
                    category="IP Hosting",
                    issue="Hosting provider could not be identified.",
                    recommendation="Verify IP ownership and hosting provider information.",
                    impact="Infrastructure visibility is reduced."
                )
            )

        # ------------------------------------------------------
        # Cloud Provider
        # ------------------------------------------------------

        cloud = data.get("cloud_provider")

        if not cloud or cloud == "Unknown":

            recommendations.append(
                Recommendation(
                    severity="Low",
                    category="IP Hosting",
                    issue="Cloud provider could not be determined.",
                    recommendation="Verify cloud infrastructure information if applicable.",
                    impact="Cloud environment cannot be identified."
                )
            )

        # ------------------------------------------------------
        # Reverse DNS
        # ------------------------------------------------------

        reverse_dns = data.get("reverse_dns")

        if not reverse_dns or reverse_dns == "Unknown":

            recommendations.append(
                Recommendation(
                    severity="Medium",
                    category="IP Hosting",
                    issue="Reverse DNS (PTR) record is missing.",
                    recommendation="Configure a reverse DNS (PTR) record for the server IP address.",
                    impact="Missing PTR records may affect email delivery and infrastructure trust."
                )
            )

        # ------------------------------------------------------
        # ASN
        # ------------------------------------------------------

        if not data.get("asn"):

            recommendations.append(
                Recommendation(
                    severity="Low",
                    category="IP Hosting",
                    issue="Autonomous System Number (ASN) information is unavailable.",
                    recommendation="Verify network routing and IP ownership.",
                    impact="Network ownership information cannot be validated."
                )
            )

        # ------------------------------------------------------
        # Organization
        # ------------------------------------------------------

        organization = data.get("organization")

        if not organization or organization == "Unknown":

            recommendations.append(
                Recommendation(
                    severity="Low",
                    category="IP Hosting",
                    issue="Hosting organization information is unavailable.",
                    recommendation="Verify IP registration and organization details.",
                    impact="Infrastructure ownership information is incomplete."
                )
            )

        return recommendations