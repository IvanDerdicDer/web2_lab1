import json
from enum import Enum, auto
from functools import wraps
from os import environ as env
from urllib.parse import quote_plus, urlencode
from itertools import count
from typing import Generator

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, jsonify, request

from project_data import *

users_dict, teams_dict, games_dict, comments_dict = get_all_data()

groups_dict = calculate_points(games_dict, teams_dict)

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


def game_id_generator(x: int) -> Generator:
    for i in count(x):
        yield str(i)


def comment_id_generator(x: int = 1) -> Generator:
    for i in count(x):
        yield str(i)


game_id_counter = game_id_generator(int(max(games_dict.keys())) + 1)
comment_id_counter = comment_id_generator()


class AuthSelector(Enum):
    NO_AUTH = auto()
    USER = auto()
    ADMIN = auto()
    USER_AND_ADMIN = auto()


def authenticate(auth_selector: AuthSelector = AuthSelector.NO_AUTH) -> bool:
    if auth_selector == AuthSelector.NO_AUTH:
        return True

    if 'user' not in session:
        return False

    user_id = session['user']['userinfo']['sub']

    if auth_selector == AuthSelector.USER:
        if user_id in users_dict and not users_dict[user_id]:
            return True

    if auth_selector == AuthSelector.ADMIN:
        if user_id in users_dict and users_dict[user_id]:
            return True

    if auth_selector == AuthSelector.USER_AND_ADMIN:
        if user_id in users_dict:
            return True

    return False


def endpoint_auth(auth_selector: AuthSelector = AuthSelector.NO_AUTH):
    def decorate(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            is_auth = authenticate(auth_selector)
            if not is_auth:
                return jsonify({'message': 'Unauthorised'}), 401

            return func(*args, **kwargs)

        return wrapper

    return decorate


@app.route("/")
def home():
    return render_template("home.html", session=session.get('user'))


@app.route('/groups')
@endpoint_auth(AuthSelector.NO_AUTH)
def groups():
    return render_template('groups.html', groups=groups_dict)


@app.route('/games')
@endpoint_auth(AuthSelector.NO_AUTH)
def games():
    return render_template('games.html', games=games_dict, is_admin=authenticate(AuthSelector.ADMIN))


@app.route('/edit_game/<game_id>')
@endpoint_auth(AuthSelector.ADMIN)
def edit_game(game_id):
    if game_id not in games_dict:
        return 'Game not found'

    return render_template('edit_game.html', game=games_dict[game_id], game_id=game_id)


@app.route('/create_game', methods=['GET'])
@endpoint_auth(AuthSelector.ADMIN)
def create_game():
    return render_template('create_game.html')


@app.route('/create_game_api', methods=['POST'])
@endpoint_auth(AuthSelector.ADMIN)
def create_game_api():
    global groups_dict

    game: Dict[str, Any] = request.form.to_dict()
    game['team_a_score'] = int(game['team_a_score'])
    game['team_b_score'] = int(game['team_b_score'])

    if game['team_a'] not in teams_dict:
        return f"Team {game['team_a']} does not exist."

    if game['team_b'] not in teams_dict:
        return f"Team {game['team_b']} does not exist."

    game_id = next(game_id_counter)

    if game_id in games_dict:
        return 'Game exists.'

    games_dict[game_id] = game

    print(json.dumps(games_dict, ensure_ascii=False, indent=4))

    groups_dict = calculate_points(games_dict, teams_dict)

    return render_template('games.html', games=games_dict, is_admin=authenticate(AuthSelector.ADMIN))


@app.route('/update_game/<game_id>', methods=['POST'])
@endpoint_auth(AuthSelector.ADMIN)
def update_game(game_id):
    global groups_dict

    game: Dict[str, Any] = request.form.to_dict()
    game['team_a_score'] = int(game['team_a_score'])
    game['team_b_score'] = int(game['team_b_score'])

    if game_id not in games_dict:
        return 'Unable to find game.'

    games_dict[game_id] = game

    groups_dict = calculate_points(games_dict, teams_dict)

    return render_template('games.html', games=games_dict, is_admin=authenticate(AuthSelector.ADMIN))


@app.route('/delete_game/<game_id>')
@endpoint_auth(AuthSelector.ADMIN)
def delete_game(game_id):
    global groups_dict

    if game_id not in games_dict:
        return 'Game not found'

    games_dict.pop(game_id)

    if game_id in comments_dict:
        comments_dict.pop(game_id)

    groups_dict = calculate_points(games_dict, teams_dict)

    return render_template('games.html', games=games_dict, is_admin=authenticate(AuthSelector.ADMIN))


@app.route('/comments/<game_id>')
@endpoint_auth(AuthSelector.NO_AUTH)
def comments(game_id):
    if game_id not in comments_dict:
        return 'Comments not found'

    user_id = None
    if 'user' in session:
        user_id = session['user']['userinfo']['sub']

    return render_template(
        'comments.html',
        comments=comments_dict[game_id],
        game_id=game_id,
        is_user=authenticate(AuthSelector.USER),
        is_admin=authenticate(AuthSelector.ADMIN),
        user_id=user_id
    )


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
