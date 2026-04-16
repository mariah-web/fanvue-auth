import os
import base64
import hashlib
import secrets
import requests
from flask import Flask, redirect, request, session, jsonify

app = Flask(__name__)
app.secret_key = "supersecretkey123"

CLIENT_ID = os.environ.get("FANVUE_CLIENT_ID")
CLIENT_SECRET = os.environ.get("FANVUE_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("FANVUE_REDIRECT_URI")

AUTH_URL = "https://auth.fanvue.com/oauth2/auth"
TOKEN_URL = "https://auth.fanvue.com/oauth2/token"

def make_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")

@app.route("/")
def home():
    return "Fanvue auth running"

@app.route("/login")
def login():
    state = secrets.token_urlsafe(24)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = make_code_challenge(code_verifier)

    session["state"] = state
    session["verifier"] = code_verifier

    url = f"{AUTH_URL}?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope=openid%20offline_access%20read:creator&state={state}&code_challenge={code_challenge}&code_challenge_method=S256"
    
    return redirect(url)

@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")

    if state != session.get("state"):
        return "Invalid state", 400

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": session.get("verifier")
    }

    res = requests.post(TOKEN_URL, data=data)
    return jsonify(res.json())
