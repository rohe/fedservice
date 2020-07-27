import logging

from cryptojwt import as_unicode
from cryptojwt.jws.jws import factory
from oidcendpoint.util import importer
from oidcmsg.context import OidcContext

from fedservice.entity_statement.collect import Collector
from fedservice.entity_statement.collect import branch2lists
from fedservice.entity_statement.create import create_entity_statement
from fedservice.entity_statement.policy import apply_policy
from fedservice.entity_statement.policy import combine_policy
from fedservice.entity_statement.policy import gather_policies
from fedservice.entity_statement.verify import eval_chain
from fedservice.entity_statement.verify import eval_policy_chain
from fedservice.utils import load_json

__author__ = 'Roland Hedberg'
__version__ = '1.0.0'

logger = logging.getLogger(__name__)


class FederationEntity(OidcContext):
    def __init__(self, entity_id, trusted_roots, authority_hints=None,
                 default_lifetime=86400, httpd=None, priority=None, entity_type='',
                 opponent_entity_type='', registration_type='', cwd='', httpc_params=None,
                 config=None):
        OidcContext.__init__(self, config, entity_id=entity_id)
        self.collector = Collector(trust_anchors=trusted_roots, http_cli=httpd, cwd=cwd,
                                   httpc_params=httpc_params, db_conf=self.db_conf)
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.opponent_entity_type = opponent_entity_type

        for iss, jwks in trusted_roots.items():
            self.keyjar.import_jwks(jwks, iss)

        self.authority_hints = authority_hints
        self.default_lifetime = default_lifetime
        self.tr_priority = priority or sorted(set(trusted_roots.keys()))
        self.registration_type = registration_type

    def collect_statement_chains(self, entity_id, statement):
        return self.collector.collect_superiors(entity_id, statement)

    def eval_chains(self, chains, entity_type='', apply_policies=True):
        """

        :param chains: A list of lists of signed JWT
        :param entity_type: The leafs entity type
        :param apply_policies: Apply metadata policies from the list on the the metadata of the
            leaf entity
        :return: List of Statement instances
        """
        if not entity_type:
            entity_type = self.opponent_entity_type

        return [eval_chain(c, self.keyjar, entity_type, apply_policies) for c in chains]

    def create_entity_statement(self, iss, sub, key_jar=None, metadata=None, metadata_policy=None,
                                authority_hints=None, lifetime=0, **kwargs):
        if not key_jar:
            key_jar = self.keyjar
        if not authority_hints:
            authority_hints = self.authority_hints
        if not lifetime:
            lifetime = self.default_lifetime

        return create_entity_statement(iss, sub, key_jar=key_jar, metadata=metadata,
                                       metadata_policy=metadata_policy,
                                       authority_hints=authority_hints, lifetime=lifetime, **kwargs)

    def get_configuration_information(self, subject_id):
        return self.collector.get_configuration_information(subject_id)

    def pick_metadata(self, statements):
        """
        Pick one statement out of the list of possible statements

        :param statements: A list of :py:class:`fedservice.entity_statement.statement.Statement
            instances
        :return: A :py:class:`fedservice.entity_statement.statement.Statement instance
        """
        if len(statements) == 1:
            # right now just pick the first:
            return statements[0]
        else:
            for fid in self.tr_priority:
                for statement in statements:
                    if statement.fo == fid:
                        return statement

        # Can only arrive here if the federations I got back and trust are not
        # in the priority list. So, just pick one

        return statements[0]

    def get_payload(self, self_signed_statement):
        _jws = as_unicode(self_signed_statement)
        _jwt = factory(_jws)
        return _jwt.jwt.payload()

    def collect_metadata_statements(self, self_signed_statement, metadata_type):
        """

        :param self_signed_statement: A Self signed Entity Statement
        :param metadata_type: One of the metadata types defined in the specification
        :return:
        """
        payload = self.get_payload(self_signed_statement)

        # collect trust chains
        _tree = self.collect_statement_chains(payload['iss'], payload)
        _node = {payload['iss']: (self_signed_statement, _tree)}
        _chains = branch2lists(_node)

        # verify the trust paths and apply policies
        return [eval_chain(c, self.keyjar, metadata_type) for c in _chains]


def create_federation_entity(entity_id, httpc_params=None, **kwargs):
    args = {"httpc_params": httpc_params}
    for param in ['trusted_roots', 'authority_hints']:
        try:
            args[param] = load_json(kwargs[param])
        except KeyError:
            pass

    for param in ['entity_type', 'priority', 'opponent_entity_type',
                  'registration_type', 'cwd']:
        try:
            args[param] = kwargs[param]
        except KeyError:
            pass

    _conf = {}
    for _key in ['keys', 'db_conf', 'issuer']:
        _value = kwargs.get(_key)
        if _value:
            _conf[_key] = _value
    if _conf:
        _conf['httpc_params'] = args['httpc_params']
        args['config'] = _conf

    federation_entity = FederationEntity(entity_id, **args)

    add_ons = kwargs.get("add_on")
    if add_ons:
        for spec in add_ons.values():
            if isinstance(spec["function"], str):
                _func = importer(spec["function"])
            else:
                _func = spec["function"]
            _func(federation_entity, **spec["kwargs"])

    return federation_entity
