from urllib.parse import urlencode
from urllib.parse import urlparse

import requests
from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory

from .cache import ESCache


class FailedConfigurationRetrieval(Exception):
    pass


def construct_well_known_url(entity_id, typ):
    p = urlparse(entity_id)
    return '{}://{}/.well-known/{}'.format(p.scheme, p.netloc, typ)


def construct_tenant_well_known_url(entity_id, typ):
    p = urlparse(entity_id)
    return '{}://{}{}/.well-known/{}'.format(p.scheme, p.netloc, p.path, typ)


def unverified_entity_statement(signed_jwt):
    _jws = factory(signed_jwt)
    return _jws.jwt.payload()


def verify_self_signed_signature(config):
    """
    Verify signature. Will raise exception if signature verification fails.

    :param config: Signed JWT
    :return: Payload of the signed JWT
    """

    payload = unverified_entity_statement(config)
    keyjar = KeyJar()
    keyjar.import_jwks(payload['jwks'], payload['iss'])

    _jwt = JWT(key_jar=keyjar)
    _val = _jwt.unpack(config)
    return _val


def get_api_endpoint(config):
    return config['metadata']['federation_entity']["federation_api_endpoint"]


def construct_entity_statement_query(api_endpoint, issuer, subject):
    return "{}?{}".format(api_endpoint,
                          urlencode({
                              "iss": issuer,
                              "sub": subject
                          }))


def active(config):
    """
    Verifies that the signature of a configuration has not timed out.

    :param config:
    :return: True/False
    """
    return True


class Collector(object):
    def __init__(self, trust_anchors, http_cli=None, insecure=False):
        self.trusted_anchors = trust_anchors
        self.trusted_ids = set(trust_anchors.keys())
        self.config_cache = ESCache(300)
        self.entity_statement_cache = ESCache(300)
        self.http_cli = http_cli or requests.request
        self.insecure = insecure

    def get_entity_statement(self, api_endpoint, issuer, subject):
        """
        Get Entity Statement by one entity about another or about itself

        :param api_endpoint: The federation API endpoint
        :param issuer: Who should issue the entity statement
        :param subject: About whom the entity statement should be
        :return: A signed JWT
        """
        _url = construct_entity_statement_query(api_endpoint, issuer, subject)
        if self.insecure:
            response = self.http_cli("GET", _url, verify=False)
        else:
            response = self.http_cli.get(_url)
        if response.status_code == 200:
            return response.text
        else:
            # log reason for failure
            return None

    def get_configuration_information(self, entity_id):
        """
        Get configuration information about an entity from itself.
        The configuration information is in the format of an Entity Statement

        :param entity_id: About whom the entity statement should be
        :return: Configuration information
        """
        if self.insecure:
            kwargs = {"verify": False}
        else:
            kwargs = {}
        response = self.http_cli('GET',
                                 construct_well_known_url(entity_id, "openid-federation"),
                                 **kwargs)
        if response.status_code == 200:
            self_signed_config = response.text
        else:  # if tenant involved
            response = self.http_cli("GET",
                                     construct_tenant_well_known_url(entity_id,
                                                                     "openid-federation"),
                                     **kwargs)
            if response.status_code == 200:
                self_signed_config = response.text
            else:
                raise FailedConfigurationRetrieval()

        return self_signed_config

    def collect_superiors(self, entity_id, statement):
        """
        Collect superiors one level at the time
        
        :param entity_id: The entity ID  
        :param statement: Signed JWT
        :return: Dictionary of superiors
        """
        superior = {}

        if 'authority_hints' not in statement:
            return superior

        for intermediate, anchor_ids in statement['authority_hints'].items():
            if anchor_ids and (self.trusted_ids.intersection(set(anchor_ids)) is None):
                # That way lies nothing I trust
                continue
            else:
                # In cache
                _info = self.config_cache[intermediate]
                if _info:
                    fed_api_endpoint = _info["metadata"]['federation_entity'][
                        'federation_api_endpoint']
                else:
                    fed_api_endpoint = None

                if not fed_api_endpoint:
                    entity_config = self.get_configuration_information(intermediate)
                    _config = verify_self_signed_signature(entity_config)
                    fed_api_endpoint = get_api_endpoint(_config)
                    # update cache
                    self.config_cache[intermediate] = _config

                cache_key = "{}!!{}".format(intermediate, entity_id)
                entity_statement = self.entity_statement_cache[cache_key]

                if entity_statement is None:
                    entity_statement = self.get_entity_statement(fed_api_endpoint, intermediate,
                                                                 entity_id)

                if entity_statement:
                    statement = unverified_entity_statement(entity_statement)
                    self.entity_statement_cache[cache_key] = statement
                    superior[intermediate] = (entity_statement,
                                              self.collect_superiors(intermediate, statement))

        return superior


def branch2lists(tree):
    res = []
    (statement, superior) = tree
    if superior:
        for issuer, branch in superior.items():
            _lists = branch2lists(branch)
            for l in _lists:
                l.append(statement)
            if not res:
                res = _lists
            else:
                res.extend(_lists)
    else:
        res.append([statement])
    return res


def main(entity_id, anchors):
    collector = Collector(anchors)
    entity_config = collector.get_configuration_information(entity_id)
    _config = verify_self_signed_signature(entity_config)
    tree = entity_config, collector.collect_superiors(entity_id, _config)
    return tree


if __name__ == '__main__':
    leaf_id = "https://example.com/rp/fed"
    trusted_anchors = {
        "anchor_id": []  # Known public keys for a trusted anchor
    }

    tree = main(leaf_id, trusted_anchors)
    chains = branch2lists(tree)
