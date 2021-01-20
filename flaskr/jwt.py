
import base64
import hashlib
import hmac
import json
import re
import uuid
import flaskr.message_handler as message_handler

from flask import jsonify
from datetime import (datetime, timedelta, timezone)
from flaskr.db import get_db

secret = b"FrEeCpcuJHPOfaYUZ8ZcVi8pzfAZkpJO"
expiration_amount_minutes = 15  # In minutes


def jwtbase64url_encode(s):
    return base64.urlsafe_b64encode(s).replace(b'=', b'')


def jwtdecode_base64(data, altchars=b'+/'):
    # https://stackoverflow.com/a/9807138
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    data = re.sub(rb'[^a-zA-Z0-9%s]+' % altchars, b'', data)  # normalize
    missing_padding = len(data) % 4
    if missing_padding:
        data += b'=' * (4 - missing_padding)
    return base64.b64decode(data, altchars)


def encryption_type(token_header):
    alg = token_header['alg']
    typ = token_header['typ']

    if typ == "JWT":
        if alg == "HS256":
            return hashlib.sha256
        return None
    return None


def __create_header():
    return json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(',', ":"), sort_keys=True).encode("utf-8")


def __create_claims(username):
    expiration_time = datetime.utcnow() + timedelta(minutes=expiration_amount_minutes)

    return json.dumps({
        # Public Claims
        "exp": expiration_time.timestamp(),
        "iat": datetime.utcnow().timestamp(),
        "username": username
    }, separators=(',', ":")).encode('utf-8')


def __verify_return_token_data(token):
    if len(token.split(".")) == 3:
        split_token = token.split(".")
        token_header = split_token[0].encode()
        token_claims = split_token[1].encode()
        token_signature = split_token[2].encode()

        decode_header = json.loads(jwtdecode_base64(token_header))
        decode_claims = json.loads(jwtdecode_base64(token_claims))

        build_signature = token_header + b"." + token_claims

        encrypt_signature = hmac.new(secret, build_signature,
                                     digestmod=encryption_type(decode_header)).digest()

        encode_signature = jwtbase64url_encode(encrypt_signature)

        if hmac.compare_digest(token_signature, encode_signature):
            return {"header": decode_header, "claims": decode_claims}

    return None


def __is_token_expired(claims):
    exp_as_date = datetime.fromtimestamp(claims['exp'])
    time_now = datetime.fromtimestamp(datetime.utcnow().timestamp())

    return time_now > exp_as_date


def create_token(username):
    encode_header = jwtbase64url_encode(
        __create_header())
    encode_claims = jwtbase64url_encode(
        __create_claims(username))
    build_signature = encode_header + b'.' + encode_claims

    # TODO: base64 encryption for secret
    signature = hmac.new(secret, build_signature,
                         digestmod=hashlib.sha256).digest()

    encode_signature = jwtbase64url_encode(signature)

    build_token = encode_header + b'.' + encode_claims + b'.' + encode_signature

    return build_token.decode('utf-8')


def verify_token(token):
    token_data = __verify_return_token_data(token)
    if token_data:
        claims = token_data['claims']
        if __is_token_expired(claims):
            message_handler.log_error("Token expired")
            return {"verification": False, "Error": "Token Expired"}
        return {"verification": True}
    else:
        message_handler.log_error("Token verification failed")
        return {"verification": False, "Error": "Token Verification Failed"}


def create_refresh_token(username):

    uuid = uuid.uuid5().hex

    db.execute('INSERT INTO refresh_tokens (username, uuid) VALUES (?, ?)',
               (username, uuid))
    db.commit()
