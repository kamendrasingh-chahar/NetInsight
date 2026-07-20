from pprint import pprint
from services.dns.lookup import DNSLookup

pprint(DNSLookup("google.com").analyze())