#!/usr/bin/env python3
# coding: utf-8

"""
    author: Leon
    contact: areuleon@gmail.com
    file: hits.py
    date: 2016/10/24
"""

import requests
from config import T01API
from protocol import T01Hit
from flask import render_template, request, jsonify
from . import app, requires_auth


@app.route('/hits_page', methods=['GET'])
@requires_auth
def hits_page():
    return render_template('hits.html')


@app.route('/hits/<id_>', methods=['GET'])
@requires_auth
def hits_get(id_):
    r = requests.get(T01API.get_rule % id_)
    if r.status_code == 200:
        items = r.json().get('saved_hits', 0)
        index, size = int(request.args.get('pageIndex', 1)), int(request.args.get('pageSize', '20'))
        r = requests.get(T01API.get_hits % (id_, (index - 1) * size, size))
        if r.status_code == 200:
            return jsonify({'data': [T01Hit.unpack(hit) for hit in r.json()], 'itemsCount': items}), r.status_code
    return jsonify(), r.status_code
