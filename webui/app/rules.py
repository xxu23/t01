#!/usr/bin/env python3
# coding: utf-8

"""
    author: Leon
    contact: areuleon@gmail.com
    file: rules.py
    date: 2016/10/24
"""

import time
import requests
from config import T01API
from protocol import T01Rule
from flask import render_template, request, jsonify
from . import app, requires_auth


def check_rules_latest():
    if not (app.config['latest'] and app.config['rules']) or time.time() - app.config['time'] > 60:
        app.config['rules'] = []
        r = requests.get(T01API.get_rule_ids)
        if r.status_code == 200:
            r = requests.get(T01API.get_rules % '&id='.join(str(_) for _ in r.json()))
            if r.status_code == 200:
                for rule in r.json():
                    rule = T01Rule.unpack(rule)
                    app.config['rules'].append(rule)
                app.config['latest'] = True
                app.config['time'] = time.time()


@app.route('/rules_page')
@requires_auth
def rules_page():
    return render_template('rules.html')


@app.route('/rules', methods=['GET'])
@requires_auth
def rules_get():
    try:
        check_rules_latest()
        rules = app.config['rules']
        rules.sort(key=lambda r: r[request.args.get('sortField', 'id')],
                   reverse=True if request.args.get('sortOrder', 'asc') == 'desc' else False)
        index, size = int(request.args.get('pageIndex', 1)), int(request.args.get('pageSize', 20))
        return jsonify(
            {'data': rules[size * (index - 1): size * index], 'itemsCount': len(rules)}), 200
    except ValueError:
        return jsonify(), 403


@app.route('/rules', methods=['POST'])
@requires_auth
def rules_add():
    try:
        r = requests.post(T01API.add_rule, json=T01Rule.pack(
            0, request.form['protocol'], request.form['sport'], request.form['dport'],
            request.form['saddr'], request.form['daddr'], request.form['action'],
            request.form['which'], request.form['match'], request.form['payload'], request.form['params']))
        if r.status_code == 200:
            app.config['latest'] = False
        return jsonify(), r.status_code
    except (KeyError, ValueError):
        return jsonify(), 403


@app.route('/rules', methods=['PUT'])
@requires_auth
def rules_put():
    try:
        res = T01Rule.pack(
            request.form['id'], request.form['protocol'], request.form['sport'], request.form['dport'],
            request.form['saddr'], request.form['daddr'], request.form['action'],
            request.form['which'], request.form['match'], request.form['payload'], request.form['params'])
        r = requests.put(T01API.put_rule % request.form['id'], json=res)
        if r.status_code == 200:
            app.config['latest'] = False
        return jsonify(T01Rule.unpack(res)), r.status_code
    except (KeyError, ValueError):
        return jsonify(), 403


@app.route('/rules', methods=['DELETE'])
@requires_auth
def rules_del():
    try:
        r = requests.delete(T01API.del_rule % request.form['id'])
        if r.status_code == 200:
            app.config['latest'] = False
        return jsonify(), r.status_code
    except (KeyError, ValueError):
        return jsonify(), 403
