from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, render_template, request

from services.analyzer.analyzer import InfrastructureAnalyzer
from utils.validators import is_valid_domain

app = Flask(__name__)


def normalize_domain(user_input: str) -> str:
    """
    Normalize user input into a clean domain.

    Accepted inputs:
        example.com
        www.example.com
        https://example.com
        https://www.example.com/
        https://www.example.com/login
        http://example.com:8080

    Returns:
        example.com
    """

    if not user_input:
        return ""

    domain = user_input.strip().lower()

    # Add scheme if user entered only a domain
    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain

    parsed = urlparse(domain)

    # Extract hostname only
    domain = parsed.hostname or ""

    # Remove leading www.
    if domain.startswith("www."):
        domain = domain[4:]

    return domain


@app.route("/")
def home():

    return render_template("index.html")

@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "404.html"
    ), 404

@app.errorhandler(500)
def server_error(error):
    return render_template("500.html"), 500


@app.route("/analyze", methods=["POST"])
def analyze():

    generated_at = datetime.now().strftime("%d %b %Y • %I:%M %p")

    # Normalize user input
    domain = normalize_domain(
        request.form.get("domain", "")
    )

    # Validate
    if not is_valid_domain(domain):

        return render_template(

            "results.html",

            domain=domain,

            report=None,

            generated_at=generated_at,

            error=(
                "Please enter a valid domain or website URL."
            )

        )

    # Run analysis
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