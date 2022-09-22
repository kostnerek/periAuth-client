from flask import Flask, jsonify, request
import requests as req
from functools import wraps

app = Flask(__name__)

auth_url = "http://localhost:3001"


def auth_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_token, refresh_token = None, None
        if "X-Access-Token" in request.headers:
            auth_token = request.headers["X-Access-Token"]
        if "X-Refresh-Token" in request.headers:
            refresh_token = request.headers["X-Refresh-Token"]
        if not auth_token and not refresh_token:
            return jsonify({"message": "Token is missing!"}), 401
        if auth_token and refresh_token:
            return jsonify({"message": "Both tokens are present!"}), 401

        if auth_token:
            res = req.get(auth_url + "/auth", headers={"X-Access-Token": auth_token})
            if res.status_code == 200:
                return (
                    jsonify({"message": "Token is valid!", "user": res.json()["user"]}),
                    200,
                )
                return func(*args, **kwargs)
            else:
                return jsonify({"message": "Invalid token!"}), 401
        else:
            res = req.get(
                url=auth_url + "/auth", headers={"X-Refresh-Token": refresh_token}
            )
            if res.status_code == 200:
                return (
                    jsonify({"message": "Token is valid!", "user": res.json()["user"]}),
                    200,
                )
                return func(*args, **kwargs)
            else:
                return jsonify({"message": "Invalid token!"}), 401

    return wrapper


@app.route("/api/login", methods=["POST"])
def authorize():
    username, password = request.json["username"], request.json["password"]
    response = req.get(
        f"{auth_url}/auth/login", json={"username": username, "password": password}
    )
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 401:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"error": "Internal server error"}), 500


@app.route("/api/protected", methods=["GET"])
@auth_required
def protected(*args, **kwargs):
    print(args, kwargs)
    # user = kwargs["user"]
    print(request.json)
    return jsonify({"message": "a"})


app.run(host="localhost", port=5050, debug=True)
