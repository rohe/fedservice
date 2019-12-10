import json
import os
from urllib.parse import unquote_plus

from fedservice.metadata_api import EntityStatementAPI


def read_info(dir, sub, typ='metadata'):
    file_name = os.path.join(dir, sub, "{}.json".format(typ))
    if os.path.isfile(file_name):
        return json.loads(open(file_name).read())
    else:
        return None


class FSEntityStatementAPI(EntityStatementAPI):
    def __init__(self, base_path, entity_id_pattern="https://{}", iss='', **kwargs):
        EntityStatementAPI.__init__(self, iss, entity_id_pattern)
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
        if iss_id not in self.keyjar:
            self.load_jwks(self.iss, self.iss, self.make_entity_id(sub))

        if sub.startswith("https%3A%2F%2F"):
            sub_id = unquote_plus(sub)
        else:
            sub_id = self.make_entity_id(sub)

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

        return data
