from cryptojwt.jws.jws import factory

from fedservice.entity_statement.statement import Statement


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


def flatten_metadata(es_list, entity_type):
    """
    Will flatten metadata for a specific entity type starting with the trust
    root

    :param es_list: List of EntityStatement instances, The first one the one
        issued by the trust root, the second the intermediate below the trust
        root and so on through the list of intermediates until the statement
        issued by the entity itself is reached.

    :param entity_type:
    :return:
    """
    res = Statement()
    res.le = es_list[0]['metadata'][entity_type]
    for es in es_list[1:]:
        res = Statement(sup=res)
        if res.restrict(es['metadata'][entity_type]) is False:
            raise ValueError('Could not flatten')

    return res