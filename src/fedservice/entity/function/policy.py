import logging
from typing import Optional

from fedservice.entity.function import Function
from fedservice.entity.function import PolicyError
from fedservice.entity.function.policy_operator import construct_evaluation_sequence
from fedservice.entity_statement.statement import TrustChain

logger = logging.getLogger(__name__)


def combine_subset_of(s1, s2):
    return list(set(s1).intersection(set(s2)))


def combine_superset_of(s1, s2):
    return list(set(s1).intersection(set(s2)))


def combine_one_of(s1, s2):
    return list(set(s1).intersection(set(s2)))


def combine_add(s1, s2):
    if isinstance(s1, list):
        set1 = set(s1)
    else:
        set1 = {s1}
    if isinstance(s2, list):
        set2 = set(s2)
    else:
        set2 = {s2}
    return list(set1.union(set2))


POLICY_FUNCTIONS = {"subset_of", "superset_of", "one_of", "add", "value", "default", "essential"}

OP2FUNC = {
    "subset_of": combine_subset_of,
    "superset_of": combine_superset_of,
    "one_of": combine_one_of,
    "add": combine_add,
}


def do_sub_one_super_add(superior, child, policy):
    if policy in superior and policy in child:
        comb = OP2FUNC[policy](superior[policy], child[policy])
        if comb:
            return comb
        else:
            raise PolicyError("Value sets doesn't overlap")
    elif policy in superior:
        return superior[policy]
    elif policy in child:
        return child[policy]


def do_value(superior, child, policy):
    if policy in superior and policy in child:
        if superior[policy] == child[policy]:
            return superior[policy]
        else:
            raise PolicyError("Not allowed to combine values")
    elif policy in superior:
        return superior[policy]
    elif policy in child:
        return child[policy]


def do_default(superior, child, policy):
    # A child's default can not override a superiors
    if policy in superior and policy in child:
        if superior['default'] == child['default']:
            return superior['default']
        else:
            raise PolicyError("Not allowed to change default")
    elif policy in superior:
        return superior[policy]
    elif policy in child:
        return child[policy]


def do_essential(superior, child, policy):
    # essential: a child can make it True if a superior has states False
    # but not the other way around

    if policy in superior and policy in child:
        if not superior[policy] and child['essential']:
            return True
        else:
            return superior[policy]
    elif policy in superior:
        return superior[policy]
    elif policy in child:  # If the essential operator is omitted, this is equivalent to including it with a value of false.
        return child[policy]
    # else:
    #     return False


DO_POLICY = {
    "add": do_sub_one_super_add,
    "value": do_value,
    "superset_of": do_sub_one_super_add,
    "subset_of": do_sub_one_super_add,
    "one_of": do_sub_one_super_add,
    "default": do_default,
    "essential": do_essential
}


def combine_claim_policy(superior, child):
    """
    Combine policy rules.
    Applying the child policy can only make the combined policy more restrictive.

    :param superior: Superior policy
    :param child: Intermediates policy
    """

    # weed out everything I don't recognize
    superior_set = set(superior).intersection(POLICY_FUNCTIONS)
    child_set = set(child).intersection(POLICY_FUNCTIONS)

    if "value" in superior_set:  # An exact value can not be restricted.
        if child_set:
            if "essential" in child_set:
                if len(child_set) == 1:
                    return {"value": superior["value"], "essential": child["essential"]}
                else:
                    raise PolicyError(
                        f"value can only be combined with essential, not {child_set}")
            elif "value" in child_set:
                if child["value"] != superior["value"]:  # Not OK
                    raise PolicyError("Child can not set another value then superior")
                else:
                    return superior
            else:
                raise PolicyError(
                    f"Not allowed combination of policies: {superior} + {child}")
        return superior
    else:
        if "essential" in superior_set and "essential" in child_set:
            # can only go from False to True
            if superior["essential"] != child["essential"] and child["essential"] is False:
                raise PolicyError("Essential can not go from True to False")

        comb_policy = superior_set.union(child_set)
        if "one_of" in comb_policy:
            if "subset_of" in comb_policy or "superset_of" in comb_policy:
                raise PolicyError("one_of can not be combined with subset_of/superset_of")

        rule = {}
        for policy in comb_policy:
            rule[policy] = DO_POLICY[policy](superior, child, policy)

        if comb_policy == {'superset_of', 'subset_of'}:
            # make sure the subset_of is a superset of superset_of.
            if set(rule['superset_of']).difference(set(rule['subset_of'])):
                raise PolicyError('superset_of not a super set of subset_of')
        elif comb_policy == {'superset_of', 'subset_of', 'default'}:
            # make sure the subset_of is a superset of superset_of.
            if set(rule['superset_of']).difference(set(rule['subset_of'])):
                raise PolicyError('superset_of not a super set of subset_of')
            if set(rule['default']).difference(set(rule['subset_of'])):
                raise PolicyError('default not a sub set of subset_of')
            if set(rule['superset_of']).difference(set(rule['default'])):
                raise PolicyError('default not a super set of subset_of')
        elif comb_policy == {'subset_of', 'default'}:
            if set(rule['default']).difference(set(rule['subset_of'])):
                raise PolicyError('default not a sub set of subset_of')
        elif comb_policy == {'superset_of', 'default'}:
            if set(rule['superset_of']).difference(set(rule['default'])):
                raise PolicyError('default not a super set of subset_of')
        elif comb_policy == {'one_of', 'default'}:
            if isinstance(rule['default'], list):
                if set(rule['default']).difference(set(rule['one_of'])):
                    raise PolicyError('default not a super set of one_of')
            else:
                if {rule['default']}.difference(set(rule['one_of'])):
                    raise PolicyError('default not a super set of one_of')
        elif comb_policy == {'subset_of', 'add'}:
            if not set(rule['add']).issubset(set(rule['subset_of'])):
                raise PolicyError('"add" not a subset of "subset"')
        elif comb_policy == {'superset_of', 'add'}:
            if not set(rule['add']).issuperset(set(rule['superset_of'])):
                raise PolicyError('"add" not a superset of "superset"')
    return rule


def combine_metadata(superior_metadata: dict, subordinate_metadata: dict) -> dict:
    sup_m_set = set(superior_metadata.keys())
    _metadata = superior_metadata
    if subordinate_metadata:
        chi_m_set = set(subordinate_metadata.keys())
        _overlap = chi_m_set.intersection(sup_m_set)
        if _overlap:
            for key in _overlap:
                if superior_metadata[key] != subordinate_metadata[key]:
                    raise PolicyError(
                        'A subordinate is not allowed to set a value different from the superiors')

        _metadata = superior_metadata.copy()
        _metadata.update(subordinate_metadata)

    return _metadata


def combine(superior: dict, subordinate: dict) -> dict:
    """

    :param superior: Dictionary with two keys metadata_policy and metadata
    :param subordinate: Dictionary with two keys metadata_policy and metadata
    :return:
    """
    _metadata = combine_metadata(superior.get('metadata', {}), subordinate.get('metadata', {}))
    if _metadata:
        superior['metadata'] = _metadata

    # Now for metadata_policies
    _sup_policy = superior.get('metadata_policy', {})
    _sub_policy = subordinate.get('metadata_policy', {})
    if _sub_policy:
        super_set = set(_sup_policy.keys())
        child_set = set(subordinate['metadata_policy'].keys())

        _metadata_policy = {}
        # appears both in superior and child
        for claim in set(super_set).intersection(child_set):
            _metadata_policy[claim] = combine_claim_policy(_sup_policy[claim], _sub_policy[claim])

        # only in super
        for claim in super_set.difference(child_set):
            _metadata_policy[claim] = _sup_policy[claim]

        # only if child
        for claim in child_set.difference(super_set):
            _metadata_policy[claim] = _sub_policy[claim]

        superior['metadata_policy'] = _metadata_policy

    return superior


def op_place(operator_name, policy_operators, index):
    while True:
        operator = policy_operators[index]
        if operator.name == operator_name:
            return index
        index += 1
        if index >= len(policy_operators):
            break
    return None

def apply_metadata_policy(metadata, metadata_policy, policy_operators):
    """
    Apply a metadata policy to a metadata statement.
    """

    policy_set = set(metadata_policy.keys())
    # metadata_set = set(metadata.keys())

    # Metadata claims that there exists a policy for
    for claim in policy_set:
        i = 0
        while True:
            _policy_op = policy_operators[i]
            if _policy_op.name in metadata_policy.get(claim, {}):
                _next = _policy_op(claim, metadata, metadata_policy)
                if _next:
                    i = op_place(_next, policy_operators, i)
                    continue
            i += 1
            if i >= len(policy_operators):
                break


    # In policy but not in metadata
    # for claim in policy_set.difference(metadata_set):
    #     if "value" in metadata_policy[claim]:
    #         metadata[claim] = metadata_policy[claim]['value']
    #     elif "add" in metadata_policy[claim]:
    #         metadata[claim] = metadata_policy[claim]['add']
    #     elif "default" in metadata_policy[claim]:
    #         metadata[claim] = metadata_policy[claim]['default']
    #
    #     if claim not in metadata:
    #         if "essential" in metadata_policy[claim] and metadata_policy[claim]["essential"]:
    #             raise PolicyError(f"Essential claim '{claim}' missing")

    return metadata



class TrustChainPolicy(Function):

    def __init__(self, upstream_get):
        Function.__init__(self, upstream_get)
        self.policy_operators = construct_evaluation_sequence()

    def gather_policies(self, chain, entity_type):
        """
        Gather and combine all the metadata policies that are defined in the trust chain
        :param chain: A list of Entity Statements
        :return: The combined metadata policy
        """

        _rule = {'metadata_policy': {}, 'metadata': {}}
        for _item in ['metadata_policy', 'metadata']:
            try:
                _rule[_item] = chain[0][_item][entity_type]
            except KeyError:
                pass

        for es in chain[1:]:
            _sub_policy = {'metadata_policy': {}, 'metadata': {}}
            for _item in ['metadata_policy', 'metadata']:
                try:
                    _sub_policy[_item] = es[_item][entity_type]
                except KeyError:
                    pass

            if _sub_policy == {'metadata_policy': {}, 'metadata': {}}:
                continue

            _overlap = set(_sub_policy['metadata_policy']).intersection(
                set(_sub_policy['metadata']))
            if _overlap:  # Not allowed
                raise PolicyError('Claim appearing both in metadata and metadata_policy not allowed')
            _rule = combine(_rule, _sub_policy)

        return _rule

    def apply_policy(self, metadata: dict, policy: dict) -> dict:
        """
        Apply a metadata policy on metadata

        :param metadata: Metadata statements
        :param policy: A dictionary with metadata and metadata_policy as keys
        :return: A metadata statement that adheres to a metadata policy
        """

        _metadata = policy.get("metadata", None)
        if _metadata:
            _metadata = _metadata.copy()
            _metadata.update(metadata)
            metadata = _metadata

        _metadata_policy = policy.get('metadata_policy', None)
        if _metadata_policy:
            metadata = apply_metadata_policy(metadata, _metadata_policy, self.policy_operators)

        # All that are in metadata but not in policy should just remain
        # metadata.update(policy.get('metadata', {}))

        return metadata

    def _policy(self, trust_chain: TrustChain, entity_type: str):
        combined_policy = self.gather_policies(trust_chain.verified_chain[:-1], entity_type)
        logger.debug("Combined policy: %s", combined_policy)
        try:
            # This should be the entity configuration
            metadata = trust_chain.verified_chain[-1]['metadata'][entity_type]
        except KeyError:
            return None
        else:
            # apply the combined metadata policies on the metadata
            trust_chain.combined_policy[entity_type] = combined_policy
            _metadata = self.apply_policy(metadata, combined_policy)
            logger.debug(f"After applied policy: {_metadata}")
            return _metadata

    def __call__(self, trust_chain: TrustChain, entity_type: Optional[str] = ''):
        """
        :param trust_chain: TrustChain instance
        :param entity_type: Which Entity Type the entity are
        """
        if len(trust_chain.verified_chain) > 1:
            if entity_type:
                trust_chain.metadata[entity_type] = self._policy(trust_chain, entity_type)
            else:
                for _type in trust_chain.verified_chain[-1]['metadata'].keys():
                    trust_chain.metadata[_type] = self._policy(trust_chain, _type)
        else:
            trust_chain.metadata = trust_chain.verified_chain[0]["metadata"][entity_type]
            trust_chain.combined_policy[entity_type] = {}


def diff2policy(new, old):
    res = {}
    for claim in set(new).intersection(set(old)):
        if new[claim] == old[claim]:
            continue
        else:
            res[claim] = {'value': new[claim]}

    for claim in set(new).difference(set(old)):
        if claim in ['contacts']:
            res[claim] = {'add': new[claim]}
        else:
            res[claim] = {'value': new[claim]}

    return res
