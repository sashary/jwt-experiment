from functools import wraps
import flaskr.jwt as jwt
import flaskr.message_handler as message_handler

from flask import Blueprint, request
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db


auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


def assert_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        verify_token = jwt.verify_token(request.headers.get('token'))

        if verify_token['verification'] == False:
            return message_handler.error(verify_token['Error'], 401)
        return f(*args, **kwargs)
    return decorated_function


@auth_bp.route('/login', methods=['GET'])
def login():
    username = request.json["username"]
    password = request.json["password"]
    db = get_db()

    if not username or not password:
        return message_handler.error("A username and password must be specified")

    user = db.execute('SELECT * FROM user WHERE username = ?',
                      (username,)).fetchone()

    if user is None or not check_password_hash(user['password'], password):
        return message_handler.error("The username and password combination could not be found", 401)

    token = jwt.create_token(user['username'])

    return message_handler.send({"user": {"token": token}})


@auth_bp.route('/test', methods=['GET'])
@assert_auth
def test():
    token = request.headers.get('token')

    return message_handler.send({"user": {"token": token}})


@auth_bp.route('/register', methods=['POST'])
def register():
    username = request.json["username"]
    password = request.json["password"]
    db = get_db()

    if not username or not password:
        return message_handler.error("A username, and password must be specified")

    if db.execute('SELECT * FROM user WHERE username = ?', (username,)).fetchone():
        return message_handler.error("This username is taken")

    try:
        db.execute('INSERT INTO user (username, password) VALUES (?, ?)',
                   (username, generate_password_hash(password)))
        db.commit()

        token = jwt.create_token(username)

        return message_handler.send(({"username": username, "token": token}))

    except:
        return message_handler.error("There was an error registering this user")

    return message_handler.error("User could not be added")
