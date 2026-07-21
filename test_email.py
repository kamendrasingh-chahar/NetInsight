from pprint import pprint
import dns.resolver
from services.dns.lookup import DNSLookup
from services.email.security import EmailSecurityAnalyzer

domain = "google.com"

dns = DNSLookup(domain).analyze()

checker = EmailSecurityAnalyzer(
    domain,
    dns["data"]
)

pprint(checker.analyze())