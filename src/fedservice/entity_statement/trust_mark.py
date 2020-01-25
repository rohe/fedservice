from cryptojwt import JWT

from fedservice import branch2lists
from fedservice import eval_chain
from fedservice.entity_statement.collect import verify_self_signed_signature
from fedservice.exception import ConstraintError
from fedservice.message import TrustMark


def create_trust_mark(entity_id, key_jar, trust_mark_id, subject='', lifetime=0, trust_mark='',
                      reference=''):
    """
    Create Trust Mark.

    :param entity_id: The issuers entity_id
    :param key_jar: A KeyJar that contains useful keys
    :param trust_mark_id: The Trust Mark identifier
    :param subject: The subject's id
    :param lifetime: For how long the trust mark should be valid (0=for ever)
    :param trust_mark: A URL pointing to a graphic trust mark
    :param reference: A URL pointing to reference material for this trust mark
    :return: A signed JWT containing the provided information
    """
    _tm = TrustMark(
        id=trust_mark_id,
    )
    if trust_mark:
        _tm["mark"] = trust_mark
    if reference:
        _tm["ref"] = reference

    if subject:
        _tm['sub'] = subject
    else:
        _tm['sub'] = entity_id

    # Create the Signed JWT representing the Trust Mark
    _jwt = JWT(key_jar=key_jar, iss=entity_id, lifetime=lifetime)
    return _jwt.pack(_tm)


def unpack_trust_mark(token, keyjar, entity_id):
    _jwt = JWT(key_jar=keyjar, msg_cls=TrustMark, allowed_sign_algs=["RS256"])
    _tm = _jwt.unpack(token)
    _tm.verify(entity_id=entity_id)
    return _tm


def get_trust_mark(federation_entity, token, entity_id, trust_anchor_id):
    _tm = unpack_trust_mark(token, federation_entity.key_jar, entity_id)

    # Get the self-signed entity statement
    entity_config = federation_entity.get_configuration_information(_tm["iss"])

    # Collect the trust chains and verify them
    statements = federation_entity.collect_metadata_statements(entity_config,
                                                               "federation_entity")
    # one of the statement chains has to end in the trust_anchor
    statement = None
    for s in statements:
        if s.iss_path[-1] == trust_anchor_id:
            statement = s
            break

    # If the trust mark is not self-signed then there should be no intermediate
    if _tm["sub"] != _tm["iss"]:
        if len(statement.iss_path) > 2:  # should only be self or self and trust anchor
            raise ConstraintError("Trust chain too long")

    return _tm


