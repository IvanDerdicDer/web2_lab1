import json
from os import environ as env
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, jsonify
from project_data import *
from functools import wraps

users, teams, games = get_all_data()

groups = calculate_points(games, teams)

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

print(env.get("AUTH0_CLIENT_ID"))

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)


def authenticate(is_admin: Optional[bool] = None) -> bool:
    if is_admin is None:
        return True

    if 'user' not in session:
        return False

    user_id = session['user']['userinfo']['sub']

    if user_id in users and is_admin == False and users[user_id] == False:
        return True

    if user_id in users and is_admin == True and users[user_id] == True:
        return True

    return False


def endpoint_auth(is_admin: Optional[bool] = None):
    def decorate(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            is_auth = authenticate(is_admin)
            if not is_auth:
                return jsonify({'message': 'Unauthorised'}), 401

            return func(*args, **kwargs)

        return wrapper

    return decorate


@app.route("/")
def home():
    return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))


@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


if __name__ == '__main__':
    url = env.get("RENDER_EXTERNAL_URL")
    port = env.get('PORT')

    if url:
        url = '127.0.0.1'

    if port:
        port = int(port)

    if not url:
        url = None

    if not port:
        port = None

    app.run(host=url, port=port)
