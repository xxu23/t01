#!/usr/bin/env python3
# coding: utf-8

"""
    author: Leon
    contact: areuleon@gmail.com
    file: __init__.py.py
    date: 2016/10/24
"""

from functools import wraps
from flask import Flask, request, Response
from config import USERNAME, PASSWORD


def check_auth(username, password):
    return username == USERNAME and password == PASSWORD


def authenticate():
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


app = Flask(__name__)
app.config['latest'] = False
app.config['rules'] = None
app.config['time'] = 0

from . import hits, info, rules, index
