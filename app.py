from flask import Flask, render_template, request

from services.dns.lookup import DNSLookup
from utils.validators import is_valid_domain

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    domain = request.form.get("domain", "").strip().lower()

    if not is_valid_domain(domain):

        return render_template(
            "results.html",
            domain=domain,
            error="Please enter a valid domain name.",
            dns_records=None
        )

    # DNS Analysis
    dns_service = DNSLookup(domain)
    dns_result = dns_service.analyze()

    return render_template(
        "results.html",
        domain=domain,
        dns_records=dns_result["data"],
        error=dns_result["error"]
    )


if __name__ == "__main__":
    app.run(debug=True)