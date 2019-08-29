import json
import os
from urllib.parse import parse_qs
from urllib.parse import urlparse

from cryptojwt.key_jar import KeyJar
from jwkest.jws import factory

from fedservice.entity_statement.collect import Collector
from fedservice.entity_statement.collect import verify_self_signed_signature
from fedservice.metadata_api.fs import make_entity_statement


def load_trust_roots(trust_root_file):
    trust_roots = json.loads(open(trust_root_file).read())
    kj = KeyJar()
    for iss, jwks in trust_roots.items():
        kj.import_jwks(jwks, iss)
    return kj


class DummyCollector(Collector):
    def __init__(self, httpd=None, trusted_roots=None, root_dir='.',
                 base_url=''):
        Collector.__init__(self, http_cli=httpd, trust_anchors=trusted_roots)
        self.root_dir = root_dir
        self.base_url = base_url

    def collect_superiors(self, subject_id, statement):
        _jwt = factory(statement)
        if _jwt:
            entity_statement = _jwt.jwt.payload()
        else:
            return None

        super = {}

        try:
            _hints = entity_statement['authority_hints']
        except KeyError:
            pass
        else:
            for intermediate, roots in _hints.items():
                super[intermediate] = self.build_path(intermediate, self.root_dir,
                                                      entity_statement['iss'])

        return statement, super

    def get_configuration_information(self, subject_id):
        jws = make_entity_statement(root_dir=self.root_dir, iss=subject_id, sub=subject_id)

        config = verify_self_signed_signature(jws)
        return config

    def get_entity_statement(self, api_endpoint, issuer, subject):
        return make_entity_statement(root_dir=self.root_dir, iss=issuer, sub=subject)

    def build_path(self, intermediate, root_dir='.', sub=''):
        """
        Builds a trust path as a sequence of signed JWTs containing entity
        statements

        :param root_dir: Where to find the dummy information to put in the entity
            statement
        :param intermediate: Which issuer to use
        :param sub: The identifier of the subject
        :return: An Issuer instance
        """
        jws = make_entity_statement(root_dir=root_dir, iss=intermediate, sub=sub)
        superior = {}

        _jwt = factory(jws)
        entity_statement = _jwt.jwt.payload()

        if 'authority_hints' in entity_statement:
            for key, sups in entity_statement['authority_hints'].items():
                superior[key] = self.build_path(key, root_dir, intermediate)

        return jws, superior


class MockResponse(object):
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class Publisher(object):
    def __init__(self, directory):
        self.dir = directory

    def __call__(self, method, url, **kwargs):
        p = urlparse(url)
        if p.path == '/.well-known/openid-federation':
            _jws = open(os.path.join(self.dir, p.netloc, p.netloc)).read().strip()
        else:
            _qs = parse_qs(p.query)
            pt = urlparse(_qs['sub'][0])
            _jws = open(os.path.join(self.dir, p.netloc, pt.netloc)).read().strip()

        return MockResponse(200, "{}".format(_jws),
                            headers={'content-type': "application/jws"})
