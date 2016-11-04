#!/usr/bin/env python2
# coding: utf-8

"""
    author: Leon
    contact: areuleon@gmail.com
    file: app.py
    date: 2016/10/18
"""

from app import app

if __name__ == '__main__':
    app.run(host="0.0.0.0", threaded=True)
