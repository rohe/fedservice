import os

from oidcendpoint.util import importer

"""
        'federation_api': {
            'class': FSEntityStatementAPI,
            'kwargs': {
                'entity_id_pattern': BASE_URL + "/eid/{}",
                'client_authn_method': None,
                'base_path': 'base_data',
                'iss': "swamid.se",
                "url_prefix": BASE_URL + "/eid"
            }
        }
"""


class SigningService:
    def __init__(self, conf, cwd=''):
        self.issuer = {}
        self.wd = cwd
        for attr, spec in conf.items():
            self.issuer[attr] = self.build_signing_service(spec)

    def build_signing_service(self, spec):
        spec['kwargs']['base_path'] = os.path.join(self.wd, spec['kwargs']["base_path"])
        if isinstance(spec["class"], str):
            _instance = importer(spec["class"])(**spec['kwargs'])
        else:
            _instance = spec["class"](**spec['kwargs'])

        return _instance