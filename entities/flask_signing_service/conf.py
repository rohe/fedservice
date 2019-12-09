from fedservice.metadata_api.fs2 import FSEntityStatementAPI

KEY_DEF = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

PORT = 6000
DOMAIN = '127.0.0.1'
SERVER_NAME = '{}:{}'.format(DOMAIN, str(PORT))
BASE_URL = 'https://{}'.format(SERVER_NAME)

CONFIG = {
    'server_info': {
        'swamid.se': {
            'class': FSEntityStatementAPI,
            'kwargs': {
                'entity_id_pattern': BASE_URL + "/eid/{}",
                'client_authn_method': None,
                'base_path': 'base_data',
                'iss': "swamid.se",
                "url_prefix": BASE_URL + "/eid"
            }
        },
        'umu.se': {
            'class': FSEntityStatementAPI,
            'kwargs': {
                'entity_id_pattern': BASE_URL + "/eid/{}",
                'client_authn_method': None,
                'base_path': 'base_data',
                'iss': "umu.se",
                "url_prefix": BASE_URL + "/eid"
            }
        },
        'lu.se': {
            'class': FSEntityStatementAPI,
            'kwargs': {
                'entity_id_pattern': BASE_URL + "/eid/{}",
                'client_authn_method': None,
                'base_path': 'base_data',
                'iss': "lu.se",
                "url_prefix": BASE_URL + "/eid"
            }
        }
    },
    'webserver': {
        'cert': '{}/certs/cert.pem',
        'key': '{}/certs/key.pem',
        'cert_chain': '',
        'port': PORT,
    }
}
