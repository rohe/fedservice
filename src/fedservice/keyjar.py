import json
from typing import Optional

from cryptojwt import KeyBundle
from cryptojwt import KeyJar
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.jwk import key_from_jwk_dict

def issuer_keys(keyjar: KeyJar, entity_id: str, format: Optional[str] = "jwk"):
    # sort of copying the functionality in KeyJar.get_issuer_keys()
    key_issuer = keyjar.return_issuer(entity_id)
    if format == "jwk":
        return [k.serialize() for k in key_issuer.all_keys()]
    else:
        return [k for k in key_issuer.all_keys()]

def import_jwks(keyjar: KeyJar, jwks: dict, entity_id: str) -> KeyJar:
    keys = []
    jar = issuer_keys(keyjar, entity_id)
    for jwk in jwks["keys"]:
        if jwk not in jar:
            jar.append(jwk)
            key = key_from_jwk_dict(jwk)
            keys.append(key)
    if keys:
        keyjar.add_keys(entity_id, keys)
    return keyjar

def import_jwks_as_json(keyjar: KeyJar, jwks: str, entity_id: str) -> KeyJar:
    return import_jwks(keyjar, json.loads(jwks), entity_id)

def import_jwks_from_file(keyjar: KeyJar, filename: str, entity_id) -> KeyJar:
    with open(filename) as jwks_file:
        keyjar = import_jwks_as_json(keyjar, jwks_file.read(), entity_id)
    return keyjar

def add_kb(keyjar: KeyJar, key_bundle: KeyBundle, entity_id: str) -> KeyJar:
    return import_jwks(keyjar, key_bundle.jwks(), entity_id)

def add_symmetric(keyjar: KeyJar, key: SYMKey, entity_id) -> KeyJar:
    jar = issuer_keys(keyjar, entity_id)
    jwk = key.serialize()
    if jwk not in jar:
        keyjar.add_symmetric(key)
    return keyjar