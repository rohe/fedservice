import logging

logger = logging.getLogger(__name__)


class PolicyError(Exception):
    pass


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

ALLOWED_COMBINATIONS = [
    {"superset_of", "subset_of"},
    {"default", "one_of"},
    {"default", "subset_of"},
    {"essential", "subset_of"},
    {"default", "superset_of"},
    {"essential", "superset_of"},
    {"essential", "one_of"},
    {"essential", "add"},
    {"essential", "value"},
    {"essential", "default"},
    {"default", "subset_of", "superset_of"},
    {"essential", "subset_of", "superset_of"}
]


def weed(policy):
    """
    Remove policy functions that are not part of the standard

    :param policy: Policy definition
    :return: Policy definition with all non-standard keys weeded out
    """
    return set(policy.keys()).difference(POLICY_FUNCTIONS)


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
    # essential: an child can make it True if a superior has states False
    # but not the other way around

    if policy in superior and policy in child:
        if not superior[policy] and child['essential']:
            return True
        else:
            return superior[policy]
    elif policy in superior:
        return superior[policy]
    elif policy in child:  # Not in superior is the same as essential=True
        return True


DO_POLICY = {
    "superset_of": do_sub_one_super_add,
    "subset_of": do_sub_one_super_add,
    "one_of": do_sub_one_super_add,
    "add": do_sub_one_super_add,
    "value": do_value,
    "default": do_default,
    "essential": do_essential
}


def combine_claim_policy(superior, child):
    """
    Combine policy rules

    :param superior: Superior policy
    :param child: Intermediates policy
    """

    comb_policy = set(superior.keys()).union(set(child.keys()))
    comb_policy = comb_policy.intersection(POLICY_FUNCTIONS)
    if len(comb_policy) > 3:
        raise PolicyError("Not allowed combination of policies")
    elif len(comb_policy) in [2, 3]:
        if comb_policy not in ALLOWED_COMBINATIONS:
            raise PolicyError("Not allowed combination of policies")

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
    return rule


def combine_policy(superior, child):
    res = {}
    sup_set = set(superior.keys())
    chi_set = set(child.keys())

    for claim in set(sup_set).intersection(chi_set):
        res[claim] = combine_claim_policy(superior[claim], child[claim])

    for claim in sup_set.difference(chi_set):
        res[claim] = superior[claim]

    for claim in chi_set.difference(sup_set):
        res[claim] = child[claim]

    return res


def gather_policies(chain, entity_type):
    """
    Gather and combine all the metadata policies that are defined in the trust chain
    :param chain: A list of Entity Statements
    :return: The combined metadata policy
    """

    try:
        combined_policy = chain[0]['metadata_policy'][entity_type]
    except KeyError:
        combined_policy = {}

    for es in chain[1:]:
        try:
            child = es['metadata_policy'][entity_type]
        except KeyError:
            pass
        else:
            combined_policy = combine_policy(combined_policy, child)

    return combined_policy


def union(val1, val2):
    if isinstance(val1, list):
        base = set(val1)
    else:
        base = {val1}

    if isinstance(val2, list):
        ext = set(val2)
    else:
        ext = {val2}
    return base.union(ext)


def apply_policy(metadata, policy):
    """
    Apply a metadata policy to a metadata statement

    :param metadata: A metadata statement
    :param policy: A metadata policy
    :return: A metadata statement that adheres to a metadata policy
    """

    metadata_set = set(metadata.keys())
    policy_set = set(policy.keys())

    # Metadata claims that there exists a policy for
    for claim in metadata_set.intersection(policy_set):
        if "subset_of" in policy[claim]:
            _val = set(policy[claim]['subset_of']).intersection(set(metadata[claim]))
            if _val:
                metadata[claim] = list(_val)
            else:
                raise PolicyError("{} not subset of {}".format(metadata[claim],
                                                               policy[claim]['subset_of']))
        elif "superset_of" in policy[claim]:
            if set(policy[claim]['superset_of']).difference(set(metadata[claim])):
                raise PolicyError("{} not superset of {}".format(metadata[claim],
                                                                 policy[claim]['superset_of']))
            else:
                pass
        elif "one_of" in policy[claim]:
            if isinstance(metadata[claim], list):
                _claim = None
                for c in metadata[claim]:
                    if c in policy[claim]['one_of']:
                        # Use the first that matches
                        _claim = c
                        break
                if _claim:
                    metadata[claim] = _claim
                else:
                    raise PolicyError(
                        "None of {} among {}".format(metadata[claim], policy[claim]['one_of']))
            else:
                if metadata[claim] in policy[claim]['one_of']:
                    pass
                else:
                    raise PolicyError(
                        "{} not among {}".format(metadata[claim], policy[claim]['one_of']))
        elif "add" in policy[claim]:
            metadata[claim] = list(union(metadata[claim], policy[claim]['add']))
        elif "value" in policy[claim]:
            metadata[claim] = policy[claim]

    # In policy but not in metadata
    for claim in policy_set.difference(metadata_set):
        if "default" in policy[claim]:
            metadata[claim] = policy[claim]['default']

        if "essential" in policy[claim] and policy[claim]["essential"]:
            raise PolicyError("Essential claim '{}' missing".format(claim))

        if "add" in policy[claim]:
            metadata[claim] = policy[claim]['add']

        if "value" in policy[claim]:
            metadata[claim] = policy[claim]['value']

    # All that are in metadata but not in policy should just remain

    return metadata


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
