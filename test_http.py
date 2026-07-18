from pprint import pprint

from services.http.status import HTTPChecker

checker = HTTPChecker("google.com")

pprint(checker.analyze())