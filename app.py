# from flask import Flask, render_template

# app = Flask(__name__)

# @app.route("/")
# def home():
#     return render_template("index.html")

# if __name__ == "__main__":
#     app.run(debug=True)

from flask import Flask, render_template, request
from dotenv import load_dotenv
import requests
import base64
import os
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)
CORS(app)

#get environment variables
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG')
# Function to check URL with VirusTotal using base64 encoding
def check_url_with_virustotal(api_key, url_to_check):
    base_url = "https://www.virustotal.com/api/v3/urls"
    
    # Encode the URL to base64 (URL-safe base64)
    encoded_url = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")

    headers = {
        "x-apikey": api_key
    }

    # Fetch the analysis results using the base64-encoded URL
    analysis_url = f"{base_url}/{encoded_url}"
    analysis_response = requests.get(analysis_url, headers=headers)
    
    if analysis_response.status_code == 200:
        results = analysis_response.json()
        stats = results["data"]["attributes"]["last_analysis_stats"]
        if stats["malicious"] > 0:
            return f"Malicious: scanner has detected the URL as harmful."
        else:
            return "The URL is safe."
    else:
        return f"Error retrieving analysis: {analysis_response.status_code}, {analysis_response.json()}"

# Route to render the main page and accept URL input
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        url = request.form.get("url")
        api_key = "81c8726e1f6c951765fecced6022a54bf4987931e667dc0f2eeeb75257fa1658"  # Replace with your VirusTotal API Key
        result = check_url_with_virustotal(api_key, url)
        return render_template("index.html", result=result)
    return render_template("index.html", result=None)

if __name__ == "__main__":
    app.run(debug=True)
