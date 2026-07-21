"""
Knull - AI-Assisted VAPT Assistant
app.py - entrypoint

Run with: python app.py
Requires: an authorization scope file at scope/authorization.json,
a GROQ_API_KEY in .env, and the underlying tools (nmap, nuclei, etc.)
installed and on PATH for whichever ones you intend to actually execute.
"""

from flask import Flask, render_template
from dotenv import load_dotenv

load_dotenv()

from routes.api import api

app = Flask(__name__)
app.register_blueprint(api)


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
