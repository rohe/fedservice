import base64
import json
import logging
from urllib.parse import quote_plus

import requests
from cryptojwt.jwt import JWT

logger = logging.getLogger(__name__)


def db_make_entity_statement(db_url, authn_info, key_jar, lifetime,
                             sign_alg='ES256', **kwargs):
    iss = kwargs['iss']

    try:
        sub = kwargs['sub']
    except KeyError:
        sub = iss

    # authn_method = ClientSecretBasic()
    # http_args = authn_method.construct({}, **authn_info)

    credentials = "{}:{}".format(authn_info['user'], authn_info['password'])
    authz = base64.b64encode(
        credentials.encode("utf-8")).decode("utf-8")
    http_args = {"headers": {"Authorization": "Basic {}".format(authz)}}

    if db_url.endswith('/'):
        _url = '{}{}'.format(db_url, quote_plus(sub))
    else:
        _url = '{}/{}'.format(db_url, quote_plus(sub))

    resp = requests.request('GET', _url, **http_args)

    if resp.status_code == 200:
        payload = json.loads(resp.text)

        packer = JWT(key_jar=key_jar, iss=iss, lifetime=lifetime,
                     sign=True, sign_alg=sign_alg)
        return packer.pack(payload)
    else:
        raise SystemError('DB not accessible "{}"'.format(resp.text))
