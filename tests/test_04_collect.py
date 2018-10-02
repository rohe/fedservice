import json
import os
from urllib.parse import urlparse, parse_qs

from cryptojwt import as_unicode
from cryptojwt.jws.jws import factory

from fedservice.entity_statement.collect import get_entity_statement, \
    collect_entity_statements


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
        pt = urlparse(_qs['target'][0])
        _jws = open(os.path.join(self.dir, p.netloc, pt.netloc)).read().strip()

        return MockResponse(200, _jws,
                            headers={'content-type': "application/jws"})


def test_get_entity_statement():
    entity_id = 'https://foodle.uninett.no'
    target = 'https://foodle.uninett.no'
    _jws = get_entity_statement(entity_id, target, httpd=Publisher('data'))
    _jwt = factory(_jws)

    assert _jwt
    msg = json.loads(as_unicode(_jwt.jwt.part[1]))
    assert msg['iss'] == entity_id
    assert msg['sub'] == target


def test_collect_entity_statements():
    entity_id = 'https://foodle.uninett.no'
    target = 'https://foodle.uninett.no'
    _jws = get_entity_statement(entity_id, target, httpd=Publisher('data'))
    _jwt = factory(_jws)

    assert _jwt
    es = json.loads(as_unicode(_jwt.jwt.part[1]))
    node = collect_entity_statements(es, httpd=Publisher('data'))
    paths = node.paths()
    assert len(paths) == 1
    assert len(paths[0]) == 3
    assert paths[0][0]["iss"] == 'https://foodle.uninett.no'
