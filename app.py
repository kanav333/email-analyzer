import os

from flask import Flask, jsonify, render_template, request
from dotenv import load_dotenv

from analyze_email import analyze_eml_bytes

load_dotenv()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    uploaded = request.files["file"]
    if not uploaded.filename:
        return jsonify({"error": "No file selected."}), 400

    if not uploaded.filename.lower().endswith(".eml"):
        return jsonify({"error": "Please upload a .eml file."}), 400

    try:
        report = analyze_eml_bytes(uploaded.read())
    except Exception as e:
        return jsonify({"error": f"Failed to parse email: {e}"}), 400

    return jsonify(report)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(debug=True, host="0.0.0.0", port=port)
