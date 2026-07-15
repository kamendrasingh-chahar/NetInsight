from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    domain = request.form.get("domain", "").strip()

    return render_template(
        "results.html",
        domain=domain
    )


if __name__ == "__main__":
    app.run(debug=True)