from pprint import pprint

from services.headers.security import SecurityHeadersChecker

checker = SecurityHeadersChecker("google.com")

pprint(checker.analyze())