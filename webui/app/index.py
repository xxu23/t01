#!/usr/bin/env python3
# coding: utf-8

"""
    author: Leon
    contact: areuleon@gmail.com
    file: index.py
    date: 2016/10/24
"""

from flask import redirect, url_for
from . import app, requires_auth


@app.route('/')
@requires_auth
def index():
    return redirect(url_for('info_page'))
