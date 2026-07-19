from dataclasses import dataclass

@dataclass
class Recommendation:
    severity: str
    category: str
    issue: str
    recommendation: str
    impact: str
    icon: str = "bi-lightbulb"