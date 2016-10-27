#!/usr/bin/env python3
# coding: utf-8

"""
    author: Leon
    contact: areuleon@gmail.com
    file: info.py
    date: 2016/10/24
"""

import requests
from config import T01API
from protocol import T01Info
from flask import render_template, jsonify
from . import app, requires_auth


@app.route('/info_page', methods=['GET'])
@requires_auth
def info_page():
    return render_template('info.html')


@app.route('/info', methods=['GET'])
@requires_auth
def info_get():
    r = requests.get(T01API.get_info)
    return jsonify(T01Info.unpack(r.json())) if r.status_code == 200 else jsonify(), r.status_code
