import os

from flask import jsonify
from datetime import (datetime, timedelta, timezone)


env = os.environ.get('FLASK_ENV') or "development"


class Message:
    def __init__(self, msg):
        self.msg = msg

    def format(self, msg_type, http_code):
        return jsonify({msg_type: self.msg, "http_status": str(http_code)})

    def format_log(self, msg_type, extra):
        extra_data = extra
        if extra == None:
            extra_data = ""
        return "[{0}] {1}  {2}".format(datetime.utcnow(), self.msg, extra_data)


def send(msg, http_code=200):
    message = Message(msg)
    return message.format("data", http_code)


def error(msg, http_code=401):
    message = Message(msg)
    return message.format("error", http_code)


def log_error(msg, extra=None):
    message = Message(msg)
    format_error = message.format_log(error, extra)
    print(format_error)
