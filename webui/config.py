#!/usr/bin/env python3
# coding: utf-8

"""
    author: Leon
    contact: areuleon@gmail.com
    file: config.py
    date: 2016/10/17
"""

import os

# T01AUTH = admin:admin
USERNAME, PASSWORD = os.environ['T01AUTH'].split(':', 1) if os.environ.get('T01AUTH') else ('admin', '1234qwer')


class T01API:
    _base = 'http://192.168.1.115:9899/'
    get_rule_ids = _base + 'ruleids'
    get_rule = _base + 'rule/%s'
    get_rules = _base + 'rules?id=%s'
    add_rule = _base + 'rules'
    put_rule = _base + 'rule/%s'
    del_rule = _base + 'rule/%s'
    get_info = _base + 'info'
    get_hits = _base + 'hits?rule_id=%s&offset=%s&limit=%s'


if __name__ == '__main__':
    pass
