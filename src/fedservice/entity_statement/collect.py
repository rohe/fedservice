import logging
from urllib.parse import urlencode
from urllib.parse import urlparse

import requests
from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac

from .cache import ESCache


logger = logging.getLogger(__name__)


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
    def __init__(self, trust_anchors, http_cli=None, insecure=False,
                 allowed_delta=300):
        self.trusted_anchors = trust_anchors
        self.trusted_ids = set(trust_anchors.keys())
        self.config_cache = ESCache(300)
        self.entity_statement_cache = ESCache(300)
        self.http_cli = http_cli or requests.request
        self.insecure = insecure
        self.allowed_delta = allowed_delta

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
            response = self.http_cli("GET", _url)
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
        :return: Configuration information as a signed JWT
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
            try:
                _config = verify_self_signed_signature(self_signed_config)
            except Exception as err:
                raise FailedConfigurationRetrieval(str(err))
        else:  # if tenant involved
            response = self.http_cli(
                "GET", construct_tenant_well_known_url(entity_id, "openid-federation"), **kwargs)
            if response.status_code == 200:
                self_signed_config = response.text
            else:
                raise FailedConfigurationRetrieval()

        return self_signed_config

    def get_federation_api_endpoint(self, intermediate):
        # In cache
        _info = self.config_cache[intermediate]
        if _info:
            fed_api_endpoint = get_api_endpoint(_info)
        else:
            fed_api_endpoint = None

        if not fed_api_endpoint:
            signed_entity_config = self.get_configuration_information(intermediate)
            if signed_entity_config is None:
                return None

            entity_config = verify_self_signed_signature(signed_entity_config)
            fed_api_endpoint = get_api_endpoint(entity_config)
            # update cache
            self.config_cache[intermediate] = entity_config

        return fed_api_endpoint

    def collect_intermediate(self, entity_id, intermediate, seen=None, max_superiors=10):
        """
        Collect information about an entity by another entity, the intermediate.
        This consist of first find the fed_api_endpoint URL for the intermediate and then
        asking the intermediate for its view of the entity.

        :param entity_id: The ID of the entity
        :param intermediate: The immediate superior
        :param seen: A list of intermediates that this process has seen. This to capture
            loops. Also used to control the allowed depth.
        :param max_superiors: The maximum number of superiors.
        :return:
        """
        # Should I stop when I reach the first trust anchor ?
        if entity_id == intermediate and entity_id in self.trusted_anchors:
            return None

        if seen is None:
            _seen = []
        else:
            _seen = seen[:]

        _seen.append(intermediate)
        # if len(_seen) > max_superiors:
        #     logger.warning("Reached max superiors. The path here was {}".format(_seen))
        #     return None

        # Try to get the entity statement from the cache
        cache_key = "{}!!{}".format(intermediate, entity_id)
        entity_statement = self.entity_statement_cache[cache_key]

        if entity_statement is not None:
            _now = utc_time_sans_frac()
            time_key = "{}!exp!{}".format(intermediate, entity_id)
            _exp = self.entity_statement_cache[time_key]
            if _now > (_exp - self.allowed_delta):
                del self.entity_statement_cache[cache_key]
                del self.entity_statement_cache[time_key]
                entity_statement = None

        if entity_statement is None:
            fed_api_endpoint = self.get_federation_api_endpoint(intermediate)
            if fed_api_endpoint is None:
                raise SystemError('Could not find federation_api endpoint')
            entity_statement = self.get_entity_statement(fed_api_endpoint, intermediate,
                                                         entity_id)
            # entity_statement is a signed JWT
            statement = unverified_entity_statement(entity_statement)
            self.entity_statement_cache[cache_key] = entity_statement
            time_key = "{}!exp!{}".format(intermediate, entity_id)
            self.entity_statement_cache[time_key] = statement["exp"]

        if entity_statement:
            intermediate_statement = self.config_cache[intermediate]
            return entity_statement, self.collect_superiors(intermediate,
                                                            intermediate_statement,
                                                            seen=_seen,
                                                            max_superiors=max_superiors)
        else:
            return None

    def collect_superiors(self, entity_id, statement, seen=None, max_superiors=1, stop_at=""):
        """
        Collect superiors one level at the time

        :param entity_id: The entity ID
        :param statement: Metadata statement
        :param seen: A list of intermediates that this process has seen. This to capture
            loops. Also used to control the allowed depth.
        :param max_superiors: The maximum number of superiors.
        :param stop_at: The ID of the trust anchor at which the trust chain should stop.
        :return: Dictionary of superiors
        """
        superior = {}
        if seen is None:
            seen = []

        if 'authority_hints' not in statement:
            return superior
        elif statement['iss'] == stop_at:
            return superior

        for intermediate in statement['authority_hints']:
            if intermediate in seen:  # loop ?!
                logger.warning("Loop detected at {}".format(intermediate))
            superior[intermediate] = self.collect_intermediate(entity_id, intermediate, seen,
                                                               max_superiors)

        return superior


def branch2lists(node):
    res = []
    for issuer, branch in node.items():
        if branch is None:
            res.append([])
            continue

        (statement, node) = branch
        if not node:
            res = [[statement]]
            continue

        _lists = branch2lists(node)
        for l in _lists:
            l.append(statement)
        if not res:
            res = _lists
        else:
            res.extend(_lists)
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
