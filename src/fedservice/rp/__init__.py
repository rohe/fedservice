import logging

from cryptojwt.key_jar import init_key_jar
import oidcrp
from oidcmsg import add_base_path
from oidcrp.util import lower_or_upper

from fedservice import create_federation_entity

logger = logging.getLogger(__name__)


class RPHandler(oidcrp.RPHandler):
    def __init__(self, base_url='', hash_seed="", keyjar=None, verify_ssl=True,
                 services=None, service_factory=None, client_configs=None,
                 client_authn_factory=None, client_cls=None,
                 state_db=None, federation_entity_config=None, httpc_params=None, **kwargs):
        oidcrp.RPHandler.__init__(self, base_url=base_url, hash_seed=hash_seed, keyjar=keyjar,
                                  verify_ssl=verify_ssl, services=services,
                                  service_factory=service_factory, client_configs=client_configs,
                                  client_authn_factory=client_authn_factory, client_cls=client_cls,
                                  state_db=state_db, httpc_params=httpc_params, **kwargs)

        self.federation_entity_config = federation_entity_config

    def init_client(self, issuer):
        client = oidcrp.RPHandler.init_client(self, issuer)
        client.service_context.federation_entity = self.init_federation_entity(issuer)
        return client

    def init_federation_entity(self, issuer):
        args = {k: v for k, v in self.federation_entity_config.items()}

        _entity_id = ''
        _cnf = self.client_configs.get(issuer)
        if _cnf:
            _entity_id = _cnf.get('entity_id')
        if not _entity_id:
            _entity_id = self.federation_entity_config['entity_id']

        if '{}' in _entity_id:
            _entity_id = _entity_id.format(issuer)
            args['entity_id'] = _entity_id

        logger.debug('Entity ID: %s', _entity_id)

        _federation_entity = create_federation_entity(httpc_params=self.httpc_params,
                                                      issuer=issuer, **args)
        _federation_entity.keyjar.httpc_params = self.httpc_params
        _federation_entity.collector.web_cert_path = self.federation_entity_config.get(
            'web_cert_path')
        return _federation_entity

    def client_setup(self, iss_id='', user=''):
        """
        First if no issuer ID is given then the identifier for the user is
        used by the webfinger service to try to find the issuer ID.
        Once the method has an issuer ID if no client is bound to this issuer
        one is created and initiated with
        the necessary information for the client to be able to communicate
        with the OP/AS that has the provided issuer ID.

        :param iss_id: The issuer ID
        :param user: A user identifier
        :return: A :py:class:`oidcservice.oidc.Client` instance
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
        issuer = self.do_provider_info(client)
        _sc = client.service_context
        try:
            _fe = _sc.federation_entity
        except AttributeError:
            _fe = None
            registration_type = 'explicit'
        else:
            registration_type = _fe.registration_type

        if registration_type == 'automatic':
            _redirect_uris = _sc.config.get("redirect_uris")
            if _redirect_uris:
                _sc.set('redirect_uris', _redirect_uris)
                _sc.set('client_id', _fe.entity_id)
                # client.client_id = _fe.entity_id
                self.hash2issuer[iss_id] = issuer
            else:
                _callbacks = self.add_callbacks(_sc)
                _sc.set('client_id', oidcrp.add_path(_fe.entity_id, _callbacks['__hex']))
        else:  # explicit
            logger.debug("Do client registration")
            self.do_client_registration(client, iss_id)

        self.issuer2rp[issuer] = client
        return client


def init_oidc_rp_handler(config, dir_path):
    rp_keys_conf = config.rp_keys
    _fed_conf = config.federation

    _httpc_params = config.httpc_params

    add_base_path(_fed_conf,
                  {
                      "keys": ['private_path', 'public_path'],
                      "": ["authority_hints", "trusted_roots"]
                  },
                  dir_path)

    _fed_conf['entity_id'] = _fed_conf['entity_id'].format(domain=config.domain, port=config.port)

    _fed_conf['web_cert_path'] = "{}/{}".format(dir_path,
                                                lower_or_upper(config.web_conf, "server_cert"))

    _path = rp_keys_conf['uri_path']
    if _path.startswith('./'):
        _path = _path[2:]
    elif _path.startswith('/'):
        _path = _path[1:]

    for client, _cnf in config.clients.items():
        for attr in ['client_id', 'entity_id']:
            _val = _cnf.get(attr)
            if _val:
                _cnf[attr] = _val.format(domain=config.domain, port=config.port)

    args = {k: v for k, v in rp_keys_conf.items() if k != "uri_path"}
    rp_keyjar = init_key_jar(**args)
    rp_keyjar.httpc_params = _httpc_params

    rph = RPHandler(base_url=config.base_url, hash_seed=config.hash_seed,
                    jwks_path=_path, client_configs=config.clients, keyjar=rp_keyjar,
                    services=config.services, httpc_params=_httpc_params,
                    federation_entity_config=_fed_conf)

    return rph
