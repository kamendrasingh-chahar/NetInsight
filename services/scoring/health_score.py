from utils.response import success_response


class HealthScoreCalculator:
    """
    Calculates the overall infrastructure health score.
    """

    def __init__(self, report):
        self.report = report

    def analyze(self):

        score = 100

        deductions = []

        dns = self.report["dns"]
        ssl = self.report["ssl"]
        http = self.report["http"]
        headers = self.report["security_headers"]

        # DNS

        if not dns["success"]:
            score -= 30
            deductions.append("DNS lookup failed.")

        # SSL

        if not ssl["success"]:
            score -= 30
            deductions.append("SSL certificate unavailable.")

        # HTTP

        if not http["success"]:
            score -= 20
            deductions.append("HTTP request failed.")

        else:

            status = http["data"]["status_code"]

            if status != 200:
                score -= 10
                deductions.append(
                    f"Unexpected HTTP status ({status})."
                )

            if http["data"]["response_time_ms"] > 500:
                score -= 5
                deductions.append(
                    "Slow response time."
                )

        # Security Headers

        if headers["success"]:

            missing = 0

            for value in headers["data"].values():

                if value == "Missing":
                    missing += 1

            score -= missing * 2

            if missing:

                deductions.append(
                    f"{missing} security headers missing."
                )

        score = max(score, 0)

        return success_response({

            "score": score,

            "deductions": deductions

        })