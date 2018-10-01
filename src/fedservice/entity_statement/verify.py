from cryptojwt.jws.jws import factory


def verify_trust_chain(es_list, key_jar):
    """

    :param es_list: List of entity statements. The entity's self-signed
        statement last.
    :param key_jar: A KeyJar instance
    :return: A sequence of verified entity statements
    """
    ves = []
    for es in es_list:
        _jwt = factory(es)
        if _jwt:
            keys = key_jar.get_jwt_verify_keys(_jwt.jwt)
            res = _jwt.verify_compact(keys=keys)
            key_jar.import_jwks(res['jwks'], res['sub'])
            ves.append(res)

    return ves
