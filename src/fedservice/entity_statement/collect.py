import logging
import os
from urllib.parse import quote_plus
from urllib.parse import urlencode
from urllib.parse import urlparse

import requests
from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jwk import x5c_to_pems
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac
from oidcmsg.exception import MissingPage
from requests.exceptions import SSLError

from fedservice.exception import UnknownCertificate
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
                 allowed_delta=300, httpc_params=None, cwd=''):
        """

        :param trust_anchors:
        :param http_cli:
        :param allowed_delta:
        :param httpc_params: Additional parameters to pass to the HTTP client
            function
        """
        self.trusted_anchors = trust_anchors
        self.trusted_ids = set(trust_anchors.keys())
        self.config_cache = ESCache(300)
        self.entity_statement_cache = ESCache(300)
        self.http_cli = http_cli or requests.request
        self.allowed_delta = allowed_delta
        self.web_cert_path = None
        self.use_ssc = False
        self.ssc_dir = ""
        self.cwd = cwd

        self.httpc_params = httpc_params or {}
        if insecure:
            self.httpc_params["verify"] = False

    def get_entity_statement(self, api_endpoint, issuer, subject):
        """
        Get Entity Statement by one entity about another or about itself

        :param api_endpoint: The federation API endpoint
        :param issuer: Who should issue the entity statement
        :param subject: About whom the entity statement should be
        :return: A signed JWT
        """
        _url = construct_entity_statement_query(api_endpoint, issuer, subject)

        if self.use_ssc:
            signed_entity_statement = self.do_ssc_seq(_url, issuer)
        else:
            signed_entity_statement = self.get_signed_entity_statement(_url, self.httpc_params)

        return  signed_entity_statement

    def _cert_path(self, entity_id):
        return os.path.join(self.ssc_dir, "{}.pem".format(quote_plus(entity_id)))

    def store_ssc_cert(self, entity_statement, entity_id):
        """
        Convert a x5c value into a list of PEM formated certificates and write them to a file.

        :param entity_statement: An Entity statement that should contain a x5c parameter.
        :param entity_id: The ID of the subject of the the Entity Statement.
        :return: The path to the created file.
        """
        x5c = entity_statement.get("x5c")
        if x5c:
            _certs = x5c_to_pems(x5c)
            _cert_path = self._cert_path(entity_id)
            with open(_cert_path, "w") as fp:
                for c in _certs:
                    fp.write(c)

            return _cert_path
        return ""

    def get_cert_path(self, entity_id):
        """
        Construct a file path and verify that it points to a file.

        :param entity_id: Significant part of the file path.
        :return: The path to an existing file.
        """
        _cert_path = self._cert_path(entity_id)
        if os.path.isfile(_cert_path):
            return _cert_path

        return None

    def get_signed_entity_statement(self, url, httpc_args):
        """

        :param url: Target URL
        :param httpc_args: Arguments for the HTTP call.
        :return: Signed EntityStatement
        """

        response = self.http_cli("GET", url, **httpc_args)
        if response.status_code == 200:
            return response.text
        elif response.status_code == 404:
            raise MissingPage("No such page: '{}'".format(url))
        else:
            raise FailedConfigurationRetrieval()

    def do_ssc_seq(self, url, entity_id, self_signed=True):
        """
        Check that the self-signed certificate in the Entity Statement really is
        the one used by the entity.

        This involves 2 steps, since I'd rather find out if something amiss early then
        late.

        :param url: The page I want to access.
        :param entity_id: The ID for the entity I want the information on.
        :return:
        """
        logger.debug("Self-signed certification sequence")
        httpc_args = self.httpc_params.copy()

        # have I seen it before
        cert_path = self.get_cert_path(entity_id)

        _signed_entity_statement = ''
        if cert_path is None:
            logger.debug("No saved certificate")
            if self_signed:  # This only works for the self-signed entity statements
                # First get the Entity Statement without verifying the entity certificate
                httpc_args["verify"] = False

                _signed_entity_statement = self.get_signed_entity_statement(url, httpc_args)

                # The get the Entity Statement while using the certificate from the entity statement
                # to verify the HTTPS certificate
                cert_path = self.store_ssc_cert(unverified_entity_statement(_signed_entity_statement),
                                                 entity_id)
                if not cert_path:
                    logger.debug('No SSL certificate in the entity metadata')
            else:  # out of luck
                raise UnknownCertificate(entity_id)

        if cert_path:
            httpc_args["verify"] = cert_path
            _signed_entity_statement = self.get_signed_entity_statement(url, httpc_args)

        return _signed_entity_statement

    def get_configuration_information(self, entity_id):
        """
        Get configuration information about an entity from itself.
        The configuration information is in the format of an Entity Statement

        :param entity_id: About whom the entity statement should be
        :return: Configuration information as a signed JWT
        """

        _url = construct_well_known_url(entity_id, "openid-federation")
        logger.debug("Config URL: %s", _url)
        try:
            if self.use_ssc:
                self_signed_config = self.do_ssc_seq(_url, entity_id)
            else:
                self_signed_config = self.get_signed_entity_statement(_url, self.httpc_params)
        except MissingPage:  # if tenant involved
            _tenant_url = construct_tenant_well_known_url(entity_id, "openid-federation")
            logger.debug("Tenant config URL: %s", _tenant_url)
            if _tenant_url != _url:
                if self.use_ssc:
                    self_signed_config = self.do_ssc_seq(_tenant_url, entity_id)
                else:
                    self_signed_config = self.get_signed_entity_statement(_tenant_url,
                                                                          self.httpc_params)
            else:
                raise MissingPage("No such page: '{}'".format(_url))
        except SSLError as err:
            logger.error(err)
            raise

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
                logger.debug("Cached entity statement timed out")
                del self.entity_statement_cache[cache_key]
                del self.entity_statement_cache[time_key]
                entity_statement = None

        if entity_statement is None:
            fed_api_endpoint = self.get_federation_api_endpoint(intermediate)
            if fed_api_endpoint is None:
                raise SystemError('Could not find federation_api endpoint')
            logger.debug("Federation API endpoint: '{}' for '{}'".format(fed_api_endpoint,
                                                                        intermediate))
            entity_statement = self.get_entity_statement(fed_api_endpoint, intermediate,
                                                         entity_id)
            # entity_statement is a signed JWT
            statement = unverified_entity_statement(entity_statement)
            logger.debug("Unverified entity statement from {} about {}: {}".format(
                fed_api_endpoint, intermediate, statement))
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
            logger.debug("Collect intermediate: %s", intermediate)
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
