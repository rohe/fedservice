import json
import os
from urllib.parse import urlparse, parse_qs

from cryptojwt import as_unicode
from cryptojwt.jws.jws import factory
from fedservice.entity_statement.collect import Collector

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


class MockResponse():
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class Publisher(object):
    def __init__(self, directory):
        self.dir = directory

    def __call__(self, method, url, **kwargs):
        p = urlparse(url)
        _qs = parse_qs(p.query)
        pt = urlparse(_qs['sub'][0])
        _jws = open(os.path.join(self.dir, p.netloc, pt.netloc)).read().strip()

        return MockResponse(200, '["{}"]'.format(_jws),
                            headers={'content-type': "application/jws"})


def test_get_entity_statement():
    entity_id = 'https://foodle.uninett.no'
    target = 'https://foodle.uninett.no'
    collector = Collector(httpd=Publisher(os.path.join(BASE_PATH,'data')))
    _jws = collector.load_entity_statements(entity_id, target)
    _jwt = factory(_jws[0])

    assert _jwt
    msg = json.loads(as_unicode(_jwt.jwt.part[1]))
    assert msg['iss'] == entity_id
    assert msg['sub'] == target


def test_collect_entity_statements():
    entity_id = 'https://foodle.uninett.no'
    target = 'https://foodle.uninett.no'
    collector = Collector(httpd=Publisher(os.path.join(BASE_PATH,'data')))
    _jws = collector.load_entity_statements(entity_id, target)
    _jwt = factory(_jws[0])

    assert _jwt

    collector = Collector(httpd=Publisher(os.path.join(BASE_PATH,'data')))
    _jws = collector.load_entity_statements(entity_id, target)
    node = collector.collect_entity_statements(_jws)
    paths = node.paths()

    assert len(paths) == 1
    assert len(paths[0]) == 3
    _jws00 = factory(paths[0][0])
    payload = _jws00.jwt.payload()
    assert payload["iss"] == 'https://foodle.uninett.no'
