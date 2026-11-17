"""APK Scanner — Flask web app. Upload an APK, get a verdict.

The scanner itself lives in scanner.py and never touches the network
or the disk; this app only serves the UI and the JSON API. Uploaded
APKs are read into memory, scanned, and discarded.
"""

import io
import os
import sys

from flask import Flask, jsonify, render_template, request

sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                "data", "examples"))

from scanner import MAX_APK_SIZE, scan_bytes  # noqa: E402
import make_examples  # noqa: E402

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_APK_SIZE

EXAMPLES = ("benign", "malicious")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/examples")
def examples():
    return jsonify({"examples": [
        {"name": "benign", "label": "Benign example APK",
         "description": "com.example.benign — INTERNET only, signed, "
                        "nothing exported."},
        {"name": "malicious", "label": "Malicious example APK",
         "description": "com.evil.fakebank — SMS permissions, exported "
                        "receiver, debuggable, unsigned."},
    ]})


@app.route("/api/example/<name>")
def example(name):
    if name not in EXAMPLES:
        return jsonify({"error": "unknown example"}), 404
    data = make_examples.build_apk_bytes(name)
    return jsonify(scan_bytes(data, "%s.apk" % name))


@app.route("/api/scan", methods=["POST"])
def scan():
    if "file" not in request.files:
        return jsonify({"error": "no file uploaded"}), 400
    upload = request.files["file"]
    if not upload.filename:
        return jsonify({"error": "no file uploaded"}), 400
    if not upload.filename.lower().endswith(".apk"):
        return jsonify({"error": "file must have a .apk extension"}), 400
    data = upload.read()
    if len(data) > MAX_APK_SIZE:
        return jsonify({"error": "APK is larger than 50 MB"}), 400
    try:
        return jsonify(scan_bytes(data, upload.filename))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
