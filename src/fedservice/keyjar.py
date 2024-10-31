from cryptojwt import KeyJar
from cryptojwt.jwk.jwk import key_from_jwk_dict

def in_keyjar(key, keyjar, entity_id):
    key_issuer = keyjar.return_issuer(entity_id)
    for bundle in key_issuer._bundles:
        if key in bundle:
            return True
    return False


def import_jwks(keyjar: KeyJar, jwks: dict, entity_id: str) -> KeyJar:
    keys = []
    for desc in jwks["keys"]:
        key = key_from_jwk_dict(desc)
        if not in_keyjar(key, keyjar, entity_id):
            keys.append(key)
    if keys:
        keyjar.add_keys(entity_id, keys)
    return keyjar
