from pprint import pprint

from services.dns.lookup import DNSLookup
from services.email.security import EmailSecurityAnalyzer

domain = "microsoft.com"

dns = DNSLookup(domain).analyze()

checker = EmailSecurityAnalyzer(
    domain,
    dns["data"]
)

pprint(checker.analyze())