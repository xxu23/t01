#!/usr/bin/env python2
# coding: utf-8

"""
    author: Leon
    contact: areuleon@gmail.com
    file: protocol.py
    date: 2016/10/17
"""

import time


def size(bytes_, suffix=''):
    """
        Human-readable file size.
    """
    sizes = [
        (1125899906842624, 'P'),
        (1099511627776, 'T'),
        (1073741824, 'G'),
        (1048576, 'M'),
        (1024, 'K'),
        (1, 'B'),
    ]
    for factor, unit in sizes:
        if bytes_ >= factor:
            amount = 1.0 * bytes_ / factor
            return '{:.1f}{}{}'.format(amount, unit, suffix)


class T01Rule:
    """
    Source rule ():
    {
        'id': 1,
        'action': 'redirect',
        'params': ['www.sina.com.cn'],
        'protocol': 'http',
        'condition': {
            'which': 'host'
            'match': 'match',
            'payload': 'www.sohu.com',
        },
        'dport': 80,
        'total_hits':	9967,
        'saved_hits':	5000
    }

    Convert to:
    {
        'id': 1,
        'action': 'redirect',
        'params': 'www.sina.com.cn',
        'protocol': 'http',
        'which': 'host',
        'match': 'match',
        'payload': 'www.sohu.com',
        'sport': 0,
        'dport': 80,
        'saddr': '0.0.0.0',
        'daddr': '0.0.0.0',
        'total_hits': 9967,
        'saved_hits': 5000
    }
    """

    @staticmethod
    def unpack(rule):
        return {
            'id': rule['id'],
            'protocol': rule.get('protocol', ''),
            'sport': rule.get('sport', 0),
            'dport': rule.get('dport', 0),
            'saddr': rule['saddr'] if rule.get('saddr', None) else '0.0.0.0',
            'daddr': rule['daddr'] if rule.get('daddr', None) else '0.0.0.0',
            'action': rule.get('action', ''),
            'match': rule['condition'].get('match', '') if rule.get('condition', None) else '',
            'which': rule['condition'].get('which', '') if rule.get('condition', None) else '',
            'payload': rule['condition'].get('payload', '') if rule.get('condition', None) else '',
            'params': '\n'.join(rule['params']) if rule.get('params', None) else '',
            'total_hits': rule.get('total_hits', 0),
            'saved_hits': rule.get('saved_hits', 0)
        }

    @staticmethod
    def pack(id_, protocol, sport, dport, saddr, daddr, action, which, match, payload, params):
        return {
            'id': int(id_),
            'protocol': protocol,
            'sport': int(sport),
            'dport': int(dport),
            'saddr': saddr if saddr != '0.0.0.0' else '',
            'daddr': daddr if daddr != '0.0.0.0' else '',
            'action': action,
            'condition': {'match': match, 'which': which, 'payload': payload},
            'params': params.split('\n') if isinstance(params, basestring) else params
        }


class T01Info:
    """
    Source info:
    {
        "iface": "em2",
        "oface": "em3",
        "upstart": 1477274500,
        "now": 1477274507,
        "total_pkts_in": 1149,
        "total_pkts_out": 3,
        "total_bytes_in": 639879,
        "total_bytes_out": 265,
        "avg_pkts_in": 213,
        "avg_pkts_out": 0,
        "avg_bytes_in": 953193,
        "avg_bytes_out": 135,
        "hits": 10374,
        "used_memory": 512000	
    }

    Convert to:
    {
        "iface": "em2",
        "oface": "em3",
        "upstart": '2016-10-24 10:01:40',
        "now": '2016-10-24 10:01:47',
        "total_pkts_in": 1149 (1,149),
        "total_pkts_out": 3 (3),
        "total_bytes_in": 639879 (624.9K/s),
        "total_bytes_out": 265 (265.0B/s),
        "avg_pkts_in": 213 (213),
        "avg_pkts_out": 0 (0),
        "avg_bytes_in": 953193 (930.9K/s),
        "avg_bytes_out": 135 (135.0B/s),
        "hits": 10374,
        "used_memory": 512000 (512KB)
    }
    """
    @staticmethod
    def unpack(info):
        return {
            'iface': info.get('iface', ''),
            'oface': info.get('oface', ''),
            'upstart': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(info.get('upstart', 0))),
            'now': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(info.get('now', 0))),
            'total_pkts_in': '{n} ({n:,})'.format(n=info.get('total_pkts_in', 0)),
            'total_pkts_out': '{n} ({n:,})'.format(n=info.get('total_pkts_out', 0)),
            'total_bytes_in': '{} ({})'.format(info.get('total_bytes_in', 0), size(info.get('total_bytes_in', 0))),
            'total_bytes_out': '{} ({})'.format(info.get('total_bytes_out', 0), size(info.get('total_bytes_out', 0))),
            'avg_pkts_in': '{n} ({n:,})'.format(n=info.get('avg_pkts_in', 0)),
            'avg_pkts_out': '{n} ({n:,})'.format(n=info.get('avg_pkts_out', 0)),
            'avg_bytes_in': '{} ({})'.format(info.get('avg_bytes_in', 0), size(info.get('avg_bytes_in', 0), '/s')),
            'avg_bytes_out': '{} ({})'.format(info.get('avg_bytes_out', 0), size(info.get('avg_bytes_out', 0), '/s')),
            'hits': info.get('hits', 0),
            'used_memory': '{} ({})'.format(info.get('used_memory', 0), size(info.get('used_memory', 0), 'B'))
        }


class T01Hit:
    """
    Source hit:
    {
        'id': 17,
        'rule_id': 1
        'time': 1477268771,
        'sport': 61509,
        'dport': 80,
        'saddr': '192.168.1.113',
        'daddr': '123.126.104.68',
        'smac': '38-2c-4a-e9-3f-b0',
        'dmac': '0c-82-68-4f-d2-4d',
    }

    Convert to:
    {
        'id': 17,
        'rule_id': 1
        'time': '2016-10-24 08:26:11',
        'sport': 61509,
        'dport': 80,
        'saddr': '192.168.1.113',
        'daddr': '123.126.104.68',
        'smac': '38-2c-4a-e9-3f-b0',
        'dmac': '0c-82-68-4f-d2-4d',
    }
    """

    @staticmethod
    def unpack(hit):
        hit['time'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(hit.get('time', 0)))
        return hit


if __name__ == '__main__':
    pass
