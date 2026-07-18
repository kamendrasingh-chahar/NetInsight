from pprint import pprint

from services.dns.lookup import DNSLookup

dns_lookup = DNSLookup("google.com")

pprint(dns_lookup.get_all_records())