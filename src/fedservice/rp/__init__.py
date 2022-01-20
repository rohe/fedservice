import logging
from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar
import oidcrp
from oidcrp import rp_handler
from oidcrp.configure import Configuration
from oidcrp.entity import Entity
from oidcrp.oauth2 import Client
from oidcrp.oidc.registration import add_callbacks
from oidcrp.util import lower_or_upper

from fedservice.entity import FederationEntity
from fedservice.entity import create_federation_entity

logger = logging.getLogger(__name__)

DEFAULT_OIDC_FED_SERVICES = {
    'provider_info': {'class': 'fedservice.rp.provider_info_discovery.FedProviderInfoDiscovery'},
    'registration': {'class': 'fedservice.rp.registration.Registration'},
}


class FederationRP(Entity):
    def __init__(self,
                 client_authn_factory: Optional[Callable] = None,
                 keyjar: Optional[KeyJar] = None,
                 config: Optional[Union[dict, Configuration]] = None,
                 services: Optional[dict] = None,
                 jwks_uri: Optional[str] = '',
                 httpc_params: Optional[dict] = None,
                 httpc: Optional[Callable] = None,
                 cwd: Optional[str] = ""):
        Entity.__init__(self,
                        client_authn_factory=client_authn_factory,
                        keyjar=keyjar,
                        config=config,
                        services=services,
                        jwks_uri=jwks_uri,
                        httpc_params=httpc_params)

        fed_conf = config.get("federation")
        if fed_conf:
            self._service_context.federation_entity = FederationEntity(config=fed_conf,
                                                                       httpc=httpc,
                                                                       cwd=cwd)


class RPHandler(rp_handler.RPHandler):
    def __init__(self, base_url='', hash_seed="", keyjar=None, verify_ssl=True,
                 services=None, service_factory=None, client_configs=None,
                 client_authn_factory=None, client_cls=None,
                 state_db=None, federation_entity_config=None, httpc_params=None, **kwargs):
        rp_handler.RPHandler.__init__(self, base_url=base_url, hash_seed=hash_seed, keyjar=keyjar,
                                      verify_ssl=verify_ssl, services=services,
                                      service_factory=service_factory,
                                      client_configs=client_configs,
                                      client_authn_factory=client_authn_factory,
                                      client_cls=client_cls,
                                      state_db=state_db, httpc_params=httpc_params, **kwargs)

        self.federation_entity_config = federation_entity_config

    def init_client(self, issuer):
        client = rp_handler.RPHandler.init_client(self, issuer)
        client.client_get("service_context").federation_entity = self.init_federation_entity(issuer)
        return client

    def init_federation_entity(self, issuer):
        args = {k: v for k, v in self.federation_entity_config["conf"].items()}

        # _cnf = self.client_configs.get(issuer).get("federation")
        # args.update(_cnf)

        _entity_id = args.get('entity_id', '')
        if not _entity_id:
            args['entity_id'] = self.federation_entity_config['entity_id']

        logger.debug('Entity ID: %s', _entity_id)

        _federation_entity = create_federation_entity(httpc_params=self.httpc_params,
                                                      issuer=issuer, **args)

        _federation_entity.context.keyjar.httpc_params = self.httpc_params
        _federation_entity.collector.web_cert_path = self.federation_entity_config.get(
            'web_cert_path')
        return _federation_entity

    def client_setup(self,
                     iss_id: Optional[str] = '',
                     user: Optional[str] = '',
                     behaviour_args: Optional[dict] = None) -> Client:
        """
        First if no issuer ID is given then the identifier for the user is
        used by the webfinger service to try to find the issuer ID.
        Once the method has an issuer ID if no client is bound to this issuer
        one is created and initiated with
        the necessary information for the client to be able to communicate
        with the OP/AS that has the provided issuer ID.

        :param iss_id: The issuer ID
        :param user: A user identifier
        :return: A :py:class:`oidcrp.oidc.Client` instance
        """

        logger.info('client_setup: iss_id={}, user={}'.format(iss_id, user))

        if not iss_id:
            if not user:
                raise ValueError('Need issuer or user')

            logger.debug("Connecting to previously unknown OP")
            temporary_client = self.init_client('')
            temporary_client.do_request('webfinger', resource=user)
        else:
            temporary_client = None

        try:
            client = self.issuer2rp[iss_id]
        except KeyError:
            if temporary_client:
                client = temporary_client
            else:
                logger.debug("Creating new client: %s", iss_id)
                client = self.init_client(iss_id)
        else:
            return client

        logger.debug("Get provider info")
        issuer = self.do_provider_info(client, behaviour_args=behaviour_args)
        _sc = client.client_get("service_context")
        try:
            _fe = _sc.federation_entity
        except AttributeError:
            _fe = None
            registration_type = 'explicit'
        else:
            registration_type = _fe.context.registration_type

        if registration_type == 'automatic':
            _redirect_uris = _sc.config.get("redirect_uris")
            if _redirect_uris:
                _sc.set('redirect_uris', _redirect_uris)
                _sc.set('client_id', _fe.context.entity_id)
                # client.client_id = _fe.entity_id
                self.hash2issuer[iss_id] = issuer
            else:
                _callbacks = add_callbacks(_sc)
                _sc.set('client_id', oidcrp.util.add_path(_fe.context.entity_id, _callbacks['__hex']))
        else:  # explicit
            logger.debug("Do client registration")
            self.do_client_registration(client, iss_id, behaviour_args=behaviour_args)

        self.issuer2rp[issuer] = client
        return client


def init_oidc_rp_handler(config, dir_path):
    rp_keys_conf = config.key_conf
    _fed_conf = config.federation

    _httpc_params = config.httpc_params

    _path = rp_keys_conf['uri_path']
    if _path.startswith('./'):
        _path = _path[2:]
    elif _path.startswith('/'):
        _path = _path[1:]

    args = {k: v for k, v in rp_keys_conf.items() if k != "uri_path"}
    rp_keyjar = init_key_jar(**args)
    rp_keyjar.httpc_params = _httpc_params

    rph = RPHandler(base_url=config.base_url, hash_seed=config.hash_seed,
                    jwks_path=_path, client_configs=config.clients, keyjar=rp_keyjar,
                    services=config.services, httpc_params=_httpc_params,
                    federation_entity_config=_fed_conf)

    return rph
