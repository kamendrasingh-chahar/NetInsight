from pprint import pprint

from services.ssl.checker import SSLChecker

checker = SSLChecker("google.com")

pprint(checker.get_certificate())