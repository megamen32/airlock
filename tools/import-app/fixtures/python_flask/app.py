"""An ordinary Flask app: no Airlock SDK imports or changes required."""

import argparse
from flask import Flask, jsonify, request


app = Flask(__name__)


@app.get("/")
def home():
    return '<h1>Existing Python application</h1><form method="post" action="/sum"><input name="a" value="7"><input name="b" value="5"><button>Calculate</button></form>'


@app.post("/sum")
def calculate():
    values = request.get_json(silent=True) or request.form
    return jsonify(total=int(values["a"]) + int(values["b"]))


@app.get("/identity")
def identity():
    return jsonify(
        user=request.headers.get("X-Airlock-User-ID"),
        authorization=request.headers.get("Authorization"),
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8181)
    args = parser.parse_args()
    app.run(host="127.0.0.1", port=args.port)
