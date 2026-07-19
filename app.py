from datetime import datetime

from flask import Flask, render_template, request

from services.analyzer.analyzer import InfrastructureAnalyzer
from utils.validators import is_valid_domain

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    # Current report generation time
    generated_at = datetime.now().strftime("%d %b %Y • %I:%M %p")

    # Get submitted domain
    domain = request.form.get(
        "domain",
        ""
    ).strip().lower()

    # Validate domain
    if not is_valid_domain(domain):

        return render_template(

            "results.html",

            domain=domain,

            report=None,

            generated_at=generated_at,

            error="Please enter a valid domain name."

        )

    # Run infrastructure analysis
    report = InfrastructureAnalyzer(
        domain
    ).analyze()

    # Render report
    return render_template(

        "results.html",

        domain=domain,

        report=report,

        generated_at=generated_at,

        error=None

    )


if __name__ == "__main__":

    app.run(debug=True)