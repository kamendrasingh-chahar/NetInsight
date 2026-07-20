from pprint import pprint

from services.cdn.detector import CDNDetector

checker = CDNDetector("youtube.com")

pprint(checker.analyze())
