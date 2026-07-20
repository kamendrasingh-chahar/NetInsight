from pprint import pprint

from services.analyzer.analyzer import InfrastructureAnalyzer

analyzer = InfrastructureAnalyzer("google.com")

result = analyzer.analyze()

pprint(result)