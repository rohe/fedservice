import json
import logging
import os
from urllib.parse import parse_qs
from urllib.parse import unquote_plus
from urllib.parse import urlparse

from fedservice.fetch_entity_statement import FetchEntityStatement

logger = logging.getLogger(__name__)


def read_info(dir, sub, typ='metadata'):
    file_name = os.path.join(dir, sub, f"{typ}.json")
    if os.path.isfile(file_name):
        return json.loads(open(file_name).read())
    else:
        return None


class FSFetchEntityStatement(FetchEntityStatement):

    def __init__(self, base_path, entity_id_pattern="https://{}", iss='', **kwargs):
        FetchEntityStatement.__init__(self, iss, entity_id_pattern)
        self.base_path = base_path
        if iss:
            # load own keys
            self.load_jwks(iss, iss, self.make_entity_id(iss))

        if 'url_prefix' in kwargs:
            self.url_prefix = kwargs['url_prefix']

    def load_jwks(self, sup, sub, sub_id):
        _jwks_file = os.path.join(self.base_path, sup, sub, "jwks.json")
        self.keyjar.import_jwks_as_json(open(_jwks_file).read(), sub_id)

    def gather_info(self, sub):
        iss_id = self.make_entity_id(self.iss)
        logger.debug('Statement Issuer ID: %s', iss_id)
        if iss_id not in self.keyjar:
            self.load_jwks(self.iss, self.iss, self.make_entity_id(sub))

        if sub.startswith("https%3A%2F%2F"):
            sub_id = unquote_plus(sub)
        else:
            sub_id = self.make_entity_id(sub)

        logger.debug('Subject ID: %s', sub_id)
        if sub_id not in self.keyjar:
            self.load_jwks(self.iss, sub, sub_id)

        data = {}
        for name, file in [("metadata", "metadata.json"),
                           ("metadata_policy", "policy.json"),
                           ("constraints", "constraints.json"),
                           ("authority_hints", "authority.json")]:
            metadata_file = os.path.join(self.base_path, self.iss, sub, file)
            if os.path.isfile(metadata_file):
                data[name] = json.loads(open(metadata_file).read())

        logger.debug("Entity statement: %s", data)
        return data


def get_netloc(url):
    p = urlparse(url)
    return p.netloc


class MockResponse(object):

    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class FSPublisher():

    def __init__(self, directory):
        self.dir = directory

    def __call__(self, method, url, **kwargs):
        if method == "GET":
            return self.get(url, **kwargs)

    def _create_entity_configuration(self, entity_id):
        fetch_api = FSFetchEntityStatement(self.dir, entity_id_pattern="https://{}", iss=entity_id)
        return fetch_api.create_entity_statement(entity_id)

    def _create_entity_statement(self, entity_id, issuer_id):
        fetch_api = FSFetchEntityStatement(self.dir, entity_id_pattern="https://{}", iss=issuer_id)
        return fetch_api.create_entity_statement(entity_id)

    def get(self, url, **kwargs):
        p = urlparse(url)
        if p.path == '/.well-known/openid-federation':
            _jws = self._create_entity_configuration(p.netloc)
        else:
            _qs = parse_qs(p.query)
            pt = urlparse(_qs['sub'][0])
            _jws = self._create_entity_statement(p.netloc, pt.netloc)

        return MockResponse(200, f"{_jws}", headers={'Content-Type': "application/jose"})
