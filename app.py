import os
from datetime import datetime
from urllib.parse import urlparse

from flask import (
    Flask,
    render_template,
    request,
    send_file,
    session,
    redirect
)
from flask_session import Session

from services.analyzer.analyzer import InfrastructureAnalyzer
from services.pdf.report_generator import PDFReportGenerator
from utils.validators import (
    is_valid_domain,
    domain_exists
)

app = Flask(__name__)

# ==========================================================
# Session Configuration
# ==========================================================

app.config["SECRET_KEY"] = os.getenv(
    "SECRET_KEY",
    "netinsight-dev-secret"
)

app.config["SESSION_TYPE"] = "filesystem"

Session(app)


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


# ==========================================================
# Routes
# ==========================================================

@app.route("/")
def home():

    return render_template(
        "index.html",
        error=None
    )


@app.route("/analyze", methods=["POST"])
def analyze():

    generated_at = datetime.now().strftime(
        "%d %b %Y • %I:%M %p"
    )

    # -----------------------------------------
    # Normalize User Input
    # -----------------------------------------

    domain = normalize_domain(
        request.form.get("domain", "")
    )

    # -----------------------------------------
    # Validate Domain Syntax
    # -----------------------------------------

    if not is_valid_domain(domain):

        return render_template(

            "index.html",

            error=(
                "Please enter a valid domain or website URL."
            )

        )

    # -----------------------------------------
    # Verify Domain Exists
    # -----------------------------------------

    if not domain_exists(domain):

        return render_template(

            "index.html",

            error=(
                "We couldn't find that website. "
                "Please check the spelling and enter a valid domain "
                "such as google.com or github.com."
            )

        )

    # -----------------------------------------
    # Run Infrastructure Analysis
    # -----------------------------------------

    report = InfrastructureAnalyzer(
        domain
    ).analyze()

    # -----------------------------------------
    # Save Report to Session
    # -----------------------------------------

    session["domain"] = domain

    session["generated_at"] = generated_at

    session["report"] = report

    # -----------------------------------------
    # Render Results
    # -----------------------------------------

    return render_template(

        "results.html",

        domain=domain,

        report=report,

        generated_at=generated_at,

        error=None

    )


@app.route("/download-report")
def download_report():

    report = session.get("report")

    domain = session.get("domain")

    generated_at = session.get("generated_at")

    if report is None:

        return redirect("/")

    pdf = PDFReportGenerator(

        domain=domain,

        report=report,

        generated_at=generated_at

    ).generate()

    return send_file(

        pdf,

        as_attachment=True,

        download_name=f"NetInsight_Report_{domain}.pdf",

        mimetype="application/pdf"

    )


# ==========================================================
# Error Pages
# ==========================================================

@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "404.html"
    ), 404


@app.errorhandler(500)
def server_error(error):

    return render_template(
        "500.html"
    ), 500


# ==========================================================
# Run Application
# ==========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )