from pprint import pprint
from services.iphosting.ip_hosting_analyzer import IPHostingAnalyzer

pprint(IPHostingAnalyzer("google.com").analyze())