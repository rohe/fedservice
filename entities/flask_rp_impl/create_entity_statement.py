from cryptojwt.key_jar import init_key_jar
from oidcservice.oidc.service import Registration

from fedservice.rp import RPHandler
from fedservice.rp.service import factory

from fedservice import create_federation_entity


def init_oidc_rp_handler(config):
    cli_conf = config.CLIENT_CONFIG
    oidc_keys_conf = config.OIDC_KEYS
    _fed_conf = cli_conf['federation']
    verify_ssl = config.VERIFY_SSL

    _kj = init_key_jar(**oidc_keys_conf)
    _kj.import_jwks_as_json(_kj.export_jwks_as_json(True, ''),
                            _fed_conf['entity_id'])
    _kj.verify_ssl = verify_ssl

    federation_entity = create_federation_entity(**_fed_conf)
    federation_entity.key_jar.verify_ssl = verify_ssl

    _path = oidc_keys_conf['public_path']
    if _path.startswith('./'):
        _path = _path[2:]
    elif _path.startswith('/'):
        _path = _path[1:]

    rph = RPHandler(base_url=config.BASEURL, hash_seed="BabyHoldOn",
                    keyjar=_kj, jwks_path=_path,
                    client_configs=config.CLIENTS,
                    services=config.SERVICES,
                    verify_ssl=verify_ssl, service_factory=factory,
                    federation_entity=federation_entity)

    return rph


if __name__ == '__main__':
    import sys
    import importlib

    sys.path.insert(0, ".")
    config = importlib.import_module(sys.argv[1])

    rph = init_oidc_rp_handler(config)

    # No registration so use the config for dynamic client
    cli = rph.init_client('')

    srv = factory('Registration', service_context=cli.service_context,
                  state_db=rph.state_db,
                  client_authn_factory=rph.client_authn_factory,
                  conf={})

    metadata = srv.construct()

    _fe = rph.federation_entity
    iss = sub = _fe.entity_id
    jws = _fe.create_entity_statement(metadata.to_dict(), iss, sub,
                                      authority_hints=_fe.authority_hints,
                                      lifetime=86400)

    with open('entity_statements/irp.jws', 'w') as fp:
        fp.write(jws)