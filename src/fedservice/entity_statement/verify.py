from cryptojwt.jws.jws import factory

from fedservice.entity_statement.policy import apply_policy
from fedservice.entity_statement.policy import gather_policies
from fedservice.entity_statement.statement import Statement


def verify_trust_chain(es_list, key_jar):
    """

    :param es_list: List of entity statements. The entity's self-signed statement last.
    :param key_jar: A KeyJar instance
    :return: A sequence of verified entity statements
    """
    ves = []
    n = len(es_list) - 1
    for es in es_list:
        _jwt = factory(es)
        if _jwt:
            keys = key_jar.get_jwt_verify_keys(_jwt.jwt)
            res = _jwt.verify_compact(keys=keys)
            try:
                _jwks = res['jwks']
            except KeyError:
                if len(ves) != n:
                    raise ValueError('Missing signing JWKS')
            else:
                key_jar.import_jwks(_jwks, res['sub'])
            ves.append(res)

    return ves


def apply_metadata_policies(es_list, entity_type):
    """
    Will apply metadata policies from the entity statements on the metadata of
    the leafs metadata.

    :param es_list: List of EntityStatement instances, The first one the one
        issued by the trust root, the second the intermediate below the trust
        root and so on through the list of intermediates until the statement
        issued by the entity itself is reached.
    :param entity_type: Type of entity
    :return: A dictionary containing the metadata
    """

    # The last entity statement is the leafs self-signed entity statement
    try:
        metadata = es_list[-1]['metadata'][entity_type]
    except KeyError:
        return None

    # Combine the metadata policies from the trust root and all intermediates
    combined_policy = gather_policies(es_list[:-1], entity_type)

    # apply the combined metadata policies on the metadata
    res = apply_policy(metadata, combined_policy)

    return res


def trust_chain_expires_at(ves):
    exp = -1
    for v in ves:
        if exp >= 0:
            if v['exp'] < exp:
                exp = v['exp']
        else:
            exp = v['exp']
    return exp


def eval_chain(chain, key_jar, entity_type, apply_policies=True):
    """

    :param chain: A chain of entity statements
    :param key_jar: A :py:class:`cryptojwt.key_jar.KeyJar` instance
    :param entity_type: Which type of metadata you want returned
    :param apply_policies: Apply policies to the metadata or not
    :returns: A Statement instances
    """
    ves = verify_trust_chain(chain, key_jar)
    tp_exp = trust_chain_expires_at(ves)

    statement = Statement(exp=tp_exp)

    if apply_policies:
        statement.metadata = apply_metadata_policies(ves, entity_type)
    else:
        # accept what ever is in the statement provided by the leaf entity
        statement.metadata = ves[-1]

    iss_path = [x['iss'] for x in ves]
    statement.fo = iss_path[0]

    iss_path.reverse()

    statement.iss_path = iss_path
    return statement
