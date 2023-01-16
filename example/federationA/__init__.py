import json
from urllib.parse import urlparse

import requests
from idpyoidc.client.defaults import DEFAULT_OIDC_SERVICES
from idpyoidc.util import QPKey

from fedservice.build_entity import FederationEntityBuilder
from fedservice.combo import FederationCombo
from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.defaults import DEFAULT_OIDC_FED_SERVICES
from fedservice.defaults import LEAF_ENDPOINT
from fedservice.defaults import TRUST_MARK_ISSUER_ENDPOINTS
from fedservice.entity import FederationEntity

SWAMID_ID = "https://127.0.0.1:7001"
SEID_ID = "https://127.0.0.1:7002"

LU_ID = "https://127.0.0.1:6001"
UMU_ID = "https://127.0.0.1:6002"

TMI_ID = "https://127.0.0.1:6003"

RPE_ID = "https://127.0.0.1:5001"
RPA_ID = "https://127.0.0.1:5002"
OP_ID = "https://127.0.0.1:5003"

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()
del TA_ENDPOINTS["resolve"]

RESPONSE_TYPES_SUPPORTED = [
    ["code"],
    ["token"],
    ["id_token"],
    ["code", "token"],
    ["code", "id_token"],
    ["id_token", "token"],
    ["code", "token", "id_token"],
    ["none"],
]

CRYPT_CONFIG = {
    "kwargs": {
        "keys": {
            "key_defs": [
                {"type": "OCT", "use": ["enc"], "kid": "password"},
                {"type": "OCT", "use": ["enc"], "kid": "salt"},
            ]
        },
        "iterations": 1,
    }
}

SESSION_PARAMS = {"encrypter": CRYPT_CONFIG}

TRUST_ANCHORS = {}

# SWAMID

SWAMID = FederationEntityBuilder(
    SWAMID_ID,
    metadata={
        "organization_name": "The SWAMID federation operator",
        "contacts": "operations@swamid.example.com"
    },
    key_conf={"key_defs": KEYDEFS,
              'uri_path': 'keys/swamid/jwks.json',
              'public_path': 'public/swamid/jwks.json',
              'private_path': 'private/swamid/jwks.json',
              'read_only': False
              }
)
SWAMID.add_endpoints(None,
                     args={
                         'subordinate': {
                             'class': 'idpyoidc.storage.abfile.AbstractFileSystem',
                             'kwargs': {
                                 'fdir': 'swamid_subordinate',
                                 'value_conv': 'idpyoidc.util.JSON',
                                 'key_conf': 'idpyoidc.util.QPKey'
                             }
                         }
                     },
                     **TA_ENDPOINTS)

TRUST_ANCHORS['swamid'] = SWAMID_ID

# SEID

SEID = FederationEntityBuilder(
    SEID_ID,
    metadata={
        "organization_name": "The SEID federation operator",
        "contacts": "operations@seid.example.com"
    },
    key_conf={"key_defs": KEYDEFS,
              'uri_path': 'keys/seid/jwks.json',
              'public_path': 'public/seid/jwks.json',
              'private_path': 'private/seid/jwks.json',
              'read_only': False
              }
)
SEID.add_endpoints(None,
                   args={
                       'subordinate': {
                           'class': 'idpyoidc.storage.abfile.AbstractFileSystem',
                           'kwargs': {
                               'fdir': 'seid_subordinate',
                               'value_conv': 'idpyoidc.util.JSON',
                               'key_conf': 'idpyoidc.util.QPKey'
                           }
                       }
                   },
                   **TA_ENDPOINTS)

TRUST_ANCHORS['seid'] = SEID_ID

# intermediates

LU = FederationEntityBuilder(
    LU_ID,
    metadata={
        "organization_name": "LU",
        "homepage_uri": "https://lu.example.com",
        "contacts": "operations@lu.example.com"
    },
    key_conf={"key_defs": KEYDEFS,
              'uri_path': 'keys/lu/jwks.json',
              'public_path': 'public/lu/jwks.json',
              'private_path': 'private/lu/jwks.json',
              'read_only': False
              },
    authority_hints=[SEID_ID, SWAMID_ID]
)
LU.add_services()
LU.add_functions()
LU.add_endpoints(metadata={"authority_hints": [LU_ID]},
                 args={
                     'subordinate': {
                         'class': 'idpyoidc.storage.abfile.AbstractFileSystem',
                         'kwargs': {
                             'fdir': 'lu_subordinate',
                             'value_conv': 'idpyoidc.util.JSON',
                             'key_conf': 'idpyoidc.util.QPKey'
                         }
                     }
                 }
                 )

UMU = FederationEntityBuilder(
    UMU_ID,
    metadata={
        "organization_name": "UmU",
        "homepage_uri": "https://umu.example.com",
        "contacts": "operations@umu.example.com"
    },
    key_conf={"key_defs": KEYDEFS,
              'uri_path': 'keys/umu/jwks.json',
              'public_path': 'public/umu/jwks.json',
              'private_path': 'private/umu/jwks.json',
              'read_only': False
              },
    authority_hints=[SEID_ID, SWAMID_ID]
)
UMU.add_services()
UMU.add_functions()
UMU.add_endpoints(metadata={"authority_hints": [SEID_ID, SWAMID_ID]},
                  args={
                      'subordinate': {
                          'class': 'idpyoidc.storage.abfile.AbstractFileSystem',
                          'kwargs': {
                              'fdir': 'umu_subordinate',
                              'value_conv': 'idpyoidc.util.JSON',
                              'key_conf': 'idpyoidc.util.QPKey'
                          }
                      }
                  }
                  )

# Leaf RPs

RPE = FederationEntityBuilder(
    RPE_ID,
    metadata={
        "organization_name": "The Explicit RP",
        "homepage_uri": "https://rpe.example.com",
        "contacts": "operations@rpe.example.com"
    },
    key_conf={"key_defs": KEYDEFS,
              'uri_path': 'keys/rpe_fe/jwks.json',
              'public_path': 'public/rpe_fe/jwks.json',
              'private_path': 'private/rpe_fe/jwks.json',
              'read_only': False
              },
    authority_hints=[LU_ID]
)
RPE.add_services()
RPE.add_functions()
RPE.add_endpoints(metadata={"authority_hints": [LU_ID]}, **LEAF_ENDPOINT)

oidc_service = DEFAULT_OIDC_SERVICES.copy()
oidc_service.update(DEFAULT_OIDC_FED_SERVICES)

RPE_CONFIG = {
    'entity_id': RPE_ID,
    'key_conf': {"key_defs": KEYDEFS},
    "federation_entity": {
        'class': 'fedservice.entity.FederationEntity',
        'kwargs': RPE.conf
    },
    "openid_relying_party": {
        'class': 'fedservice.rp.ClientEntity',
        'kwargs': {
            'config': {
                'client_id': RPE_ID,
                'client_secret': 'a longesh password',
                'redirect_uris': [f'{RPE_ID}/authz_cb'],
                "keys": {"uri_path": "keys/rpe/jwks.json",
                         "key_defs": KEYDEFS,
                         'public_path': 'public/rpe/jwks.json',
                         'private_path': 'private/rpe/jwks.json',
                         'read_only': False
                         },
                "metadata": {
                    "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                    "id_token_signed_response_alg": "ES256",
                    "token_endpoint_auth_method": "client_secret_basic",
                    "token_endpoint_auth_signing_alg": "ES256"
                }
            },
            "services": oidc_service
        }
    }
}

RPA = FederationEntityBuilder(
    RPA_ID,
    metadata={
        "organization_name": "The Automatic RP",
        "homepage_uri": "https://rpa.example.com",
        "contacts": "operations@rpa.example.com"
    },
    key_conf={"key_defs": KEYDEFS,
              'uri_path': 'keys/rpa_fe/jwks.json',
              'public_path': 'public/rpa_fe/jwks.json',
              'private_path': 'private/rpa_fe/jwks.json',
              'read_only': False
              },
    authority_hints=[LU_ID]
)
RPA.add_services()
RPA.add_functions()
RPA.add_endpoints(metadata={"authority_hints": [LU_ID]}, **LEAF_ENDPOINT)

RPA_CONFIG = {
    'entity_id': RPA_ID,
    'key_conf': {"key_defs": KEYDEFS},
    "federation_entity": {
        'class': 'fedservice.entity.FederationEntity',
        'kwargs': RPA.conf
    },
    "openid_relying_party": {
        'class': 'fedservice.rp.ClientEntity',
        'kwargs': {
            'config': {
                'client_id': RPA_ID,
                'client_secret': 'a longesh password',
                'redirect_uris': [f'{RPA_ID}/authz_cb'],
                "keys": {"uri_path": "keys/rpa/jwks.json",
                         "key_defs": KEYDEFS,
                         'public_path': 'public/rpa/jwks.json',
                         'private_path': 'private/rpa/jwks.json',
                         'read_only': False
                         },
                "metadata": {
                    "grant_types": ['authorization_code', 'implicit', 'refresh_token'],
                    "id_token_signed_response_alg": "ES256",
                    "token_endpoint_auth_method": "client_secret_basic",
                    "token_endpoint_auth_signing_alg": "ES256"
                }
            },
            "services": oidc_service
        }
    }
}

# Leaf OP

OP = FederationEntityBuilder(
    OP_ID,
    metadata={
        "organization_name": "The OP operator",
        "homepage_uri": "https://op.example.com",
        "contacts": "operations@op.example.com"
    },
    key_conf={"key_defs": KEYDEFS,
              'uri_path': 'keys/op_fe/jwks.json',
              'public_path': 'public/op_fe/jwks.json',
              'private_path': 'private/op_fe/jwks.json',
              'read_only': False
              },
    authority_hints=[UMU_ID]
)
OP.add_services()
OP.add_functions()
OP.add_endpoints(metadata={"authority_hints": [UMU_ID]}, **LEAF_ENDPOINT)

OP_CONFIG = {
    'entity_id': OP_ID,
    'key_conf': {"key_defs": KEYDEFS},
    "federation_entity": {
        'class': 'fedservice.entity.FederationEntity',
        'kwargs': OP.conf
    },
    "openid_provider": {
        'class': 'fedservice.op.ServerEntity',
        'kwargs': {
            'config': {
                "issuer": "https://example.com/",
                "httpc_params": {"verify": False, "timeout": 1},
                "capabilities": {
                    "subject_types_supported": ["public", "pairwise", "ephemeral"],
                    "grant_types_supported": [
                        "authorization_code",
                        "implicit",
                        "urn:ietf:params:oauth:grant-type:jwt-bearer",
                        "refresh_token",
                    ],
                },
                "token_handler_args": {
                    "jwks_def": {
                        "private_path": "keys/private/op_th_jwks.json",
                        "read_only": False,
                        "key_defs": [
                            {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"}],
                    },
                    "code": {"lifetime": 600, "kwargs": {"crypt_conf": CRYPT_CONFIG}},
                    "token": {
                        "class": "idpyoidc.server.token.jwt_token.JWTToken",
                        "kwargs": {
                            "lifetime": 3600,
                            "add_claims_by_scope": True,
                            "aud": ["https://example.org/appl"],
                        },
                    },
                    "refresh": {
                        "class": "idpyoidc.server.token.jwt_token.JWTToken",
                        "kwargs": {
                            "lifetime": 3600,
                            "aud": ["https://example.org/appl"],
                        },
                    },
                    "id_token": {
                        "class": "idpyoidc.server.token.id_token.IDToken",
                        "kwargs": {
                            "base_claims": {
                                "email": {"essential": True},
                                "email_verified": {"essential": True},
                            }
                        },
                    },
                },
                "keys": {"key_defs": KEYDEFS,
                         "uri_path": "keys/op/jwks.json",
                         'public_path': 'public/op/jwks.json',
                         'private_path': 'private/op/jwks.json',
                         'read_only': False
                         },
                "endpoint": {
                    "registration": {
                        "path": "registration",
                        "class": 'fedservice.op.registration.Registration',
                        "kwargs": {"client_auth_method": None},
                    },
                    "authorization": {
                        "path": "authorization",
                        "class": 'fedservice.op.authorization.Authorization',
                        "kwargs": {
                            "response_types_supported": [" ".join(x) for x in
                                                         RESPONSE_TYPES_SUPPORTED],
                            "response_modes_supported": ["query", "fragment", "form_post"],
                            "claim_types_supported": [
                                "normal",
                                "aggregated",
                                "distributed",
                            ],
                            "claims_parameter_supported": True,
                            "request_parameter_supported": True,
                            "request_uri_parameter_supported": True,
                        },
                    },
                    "token": {
                        "path": "token",
                        "class": 'idpyoidc.server.oidc.token.Token',
                        "kwargs": {
                            "client_authn_method": [
                                "client_secret_post",
                                "client_secret_basic",
                                "client_secret_jwt",
                                "private_key_jwt",
                            ]
                        },
                    },
                    "userinfo": {
                        "path": "userinfo",
                        "class": 'idpyoidc.server.oidc.userinfo.UserInfo',
                        "kwargs": {}
                    },
                },
                "template_dir": "template",
                "session_params": SESSION_PARAMS,
            }
        }
    }
}

# Trust Mark Issuer

TMI = FederationEntityBuilder(
    TMI_ID,
    metadata={
        "organization_name": "The Trust Mark Issuer",
        "homepage_uri": "https://tmi.example.com",
        "contacts": "operations@tmi.example.com"
    },
    key_conf={"key_defs": KEYDEFS,
              'uri_path': 'keys/tmi_fe/jwks.json',
              'public_path': 'public/tmi_fe/jwks.json',
              'private_path': 'private/tmi_fe/jwks.json',
              'read_only': False
              },
    authority_hints=[SWAMID_ID]
)
_endpoints = TRUST_MARK_ISSUER_ENDPOINTS
_endpoints['status']['kwargs']['trust_marks'] = {TMI_ID: {"ref": "https://tm.example.com/swamid"}}
TMI.add_endpoints(**_endpoints)
TMI.conf['server']['kwargs']['endpoint']['status']['kwargs'][
    'trust_mark_issuer'] = {
    'class': 'fedservice.trust_mark_issuer.TrustMarkIssuer',
    'kwargs': {
        'key_conf': {"key_defs": KEYDEFS, 'uri_path': 'keys/tmi/jwks.json'}
    }
}
TMI_SERVICES = {
    "entity_configuration": {
        "class": 'fedservice.entity.client.entity_configuration.EntityConfiguration',
        "kwargs": {}
    },
    "trust_mark_status": {
        "class": 'fedservice.entity.client.trust_mark_status.TrustMarkStatus',
        "kwargs": {}
    }
}
TMI.add_services(**TMI_SERVICES)
# TMI.add_functions()

# --------------------------- Instances, add Trust Anchors -----------------------------------------

# TRUST ANCHORs
_swamid = FederationEntity(**SWAMID.conf, httpc=requests, httpc_params={'verify': False})
_seid = FederationEntity(**SEID.conf, httpc=requests, httpc_params={'verify': False})

ANCHOR = {
    SWAMID_ID: _swamid.keyjar.export_jwks(),
    SEID_ID: _seid.keyjar.export_jwks()
}

# Intermediates
UMU.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
    'trust_anchors'] = ANCHOR
_umu = FederationEntity(**UMU.conf, httpc=requests, httpc_params={'verify': False})

LU.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
    'trust_anchors'] = ANCHOR
_lu = FederationEntity(**LU.conf, httpc=requests, httpc_params={'verify': False})

# Leaf RPs

RPA.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
    'trust_anchors'] = ANCHOR
_rpa = FederationCombo(RPA_CONFIG)

RPE.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
    'trust_anchors'] = ANCHOR
_rpe = FederationCombo(RPE_CONFIG)

# Leaf OP
OP.conf['function']['kwargs']['functions']['trust_chain_collector']['kwargs'][
    'trust_anchors'] = ANCHOR
_op = FederationCombo(OP_CONFIG)

# Trust Mark Issuer
_tmi = FederationEntity(**TMI.conf)


# -----------------------------------------------------------------------------------------------

def store_subordinate_info(authority, subordinate):
    # Create subordinate information and write it to the 'subordinate' directory
    _info = {
        "jwks": subordinate.keyjar.export_jwks(),
        'authority_hints': [authority.conf['entity_id']]
    }
    _subordinate_dir = authority.conf['server']['kwargs']['subordinate']['kwargs']['fdir']
    fname = f'{_subordinate_dir}/{QPKey().serialize(subordinate.entity_id)}'
    with open(fname, 'w') as f:
        f.write(json.dumps(_info))


# SWAMID subordinates == LU, UMU and TMI

store_subordinate_info(SWAMID, _umu)
store_subordinate_info(SWAMID, _lu)
store_subordinate_info(SWAMID, _tmi)

# SEID subordinates == LU and UMU

store_subordinate_info(SEID, _umu)
store_subordinate_info(SEID, _lu)

# LU subordinates == RPA and RPE
store_subordinate_info(LU, _rpa)
store_subordinate_info(LU, _rpe)

# UMU subordinate == OP

store_subordinate_info(UMU, _op)

overall = {
    "logging": {
        "version": 1,
        "disable_existing_loggers": False,
        "root": {
            "handlers": [
                "default",
                "console"
            ],
            "level": "DEBUG"
        },
        "loggers": {
            "entity": {
                "level": "DEBUG"
            }
        },
        "handlers": {
            "default": {
                "class": "logging.FileHandler",
                "filename": "XXX.log",
                "formatter": "default"
            },
            "console": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": "default"
            }
        },
        "formatters": {
            "default": {
                "format": "%(asctime)s %(name)s %(levelname)s %(message)s"
            }
        }
    },
    "webserver": {
        "server_cert": "certs/example.crt",
        "server_key": "certs/example.key",
        "cert_chain": None,
        "port": 0,
        "domain": "127.0.0.1",
        "debug": True
    }
}

# for entity in [SWAMID, SEID, TMI, UMU, LU]:
#     print(10 * '=' + entity.conf['entity_id'] + 10 * '=')
#     print(json.dumps(entity.conf, sort_keys=True, indent=2))
#
# for combo in [RPA_CONFIG, RPE_CONFIG, OP_CONFIG]:
#     print(10 * '=' + combo['entity_id'] + 10 * '=')
#     print(json.dumps(combo, sort_keys=True, indent=2))

for entity in [SWAMID, SEID, TMI, UMU, LU]:
    fname = f'{QPKey().serialize(entity.conf["entity_id"])}'
    _port = urlparse(entity.conf["entity_id"]).port
    _name = entity.conf['metadata']['contacts'].split('@')[1].split('.')[0]
    conf = overall.copy()
    conf['logging']['handlers']['default']['filename'] = f'{_name}_debug.log'
    conf['webserver']['port'] = _port
    conf['configuration'] = {
        "federation_entity": {
            'class': 'fedservice.entity.FederationEntity',
            'kwargs': entity.conf
        }}

    with open(f'entities/{fname}.json', 'w') as f:
        f.write(json.dumps(conf, sort_keys=True, indent=2))

for combo in [RPA_CONFIG, RPE_CONFIG, OP_CONFIG]:
    fname = f'{QPKey().serialize(combo["entity_id"])}'
    _port = urlparse(entity.conf["entity_id"]).port
    _name = combo['federation_entity']['kwargs']['metadata']['contacts'].split('@')[1].split('.')[0]
    conf = overall.copy()
    conf['logging']['handlers']['default']['filename'] = f'{_name}_debug.log'
    conf['webserver']['port'] = _port
    conf['configuration'] = combo
    with open(f'entities/{fname}.json', 'w') as f:
        f.write(json.dumps(conf, sort_keys=True, indent=2))

with open('trust_anchors', 'w') as f:
    f.write(json.dumps(TRUST_ANCHORS))
