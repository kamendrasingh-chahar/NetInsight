from utils.response import success_response


class HealthScoreCalculator:
    """
   Calculates the overall infrastructure health score.
    """

    def __init__(self, report):
        self.report = report

    def analyze(self):

        breakdown = {}

        # ----------------------------------
        # DNS (20)
        # ----------------------------------

        dns_score = 20 if self.report["dns"]["success"] else 0

        breakdown["DNS"] = {
            "score": dns_score,
            "max": 20
        }

        # ----------------------------------
        # SSL (20)
        # ----------------------------------

        ssl_score = 20 if self.report["ssl"]["success"] else 0

        breakdown["SSL"] = {
            "score": ssl_score,
            "max": 20
        }

        # ----------------------------------
        # HTTP (15)
        # ----------------------------------

        http_score = 0

        if self.report["http"]["success"]:

            http = self.report["http"]["data"]

            if http["status_code"] == 200:
                http_score += 10

            if http["response_time_ms"] < 500:
                http_score += 5

        breakdown["HTTP"] = {
            "score": http_score,
            "max": 15
        }

        # ----------------------------------
        # Security Headers (25)
        # ----------------------------------

        header_score = 0

        if self.report["security_headers"]["success"]:

            headers = self.report["security_headers"]["data"]["headers"]

            total_headers = len(headers)

            present_headers = sum(
                1
                for header in headers.values()
                if header["present"]
            )

            header_score = round(
                (present_headers / total_headers) * 25
            )

        breakdown["Security Headers"] = {
            "score": header_score,
            "max": 25
        }

        # ----------------------------------
        # CDN (10)
        # ----------------------------------

        cdn_score = 0

        if (
            self.report["cdn"]["success"]
            and
            self.report["cdn"]["data"]["detected"]
        ):
            cdn_score = 10

        breakdown["CDN"] = {
            "score": cdn_score,
            "max": 10
        }

        # ----------------------------------
        # Email Security (10)
        # ----------------------------------

        email_score = 0

        if self.report["email_security"]["success"]:

            email = self.report["email_security"]["data"]

            if email["mx"]:
                email_score += 2.5

            if email["spf"]:
                email_score += 2.5

            if email["dmarc"]:
                email_score += 2.5

            if email["dkim"]["enabled"]:
                email_score += 2.5

        breakdown["Email Security"] = {
            "score": round(email_score),
            "max": 10
        }

        # ----------------------------------
        # Final Score
        # ----------------------------------

        total_score = sum(
            item["score"]
            for item in breakdown.values()
        )

        return success_response({

            "score": total_score,

            "breakdown": breakdown

        })