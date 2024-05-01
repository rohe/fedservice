__author__ = 'Roland Hedberg'
__version__ = '5.0.0'

from fedservice.entity_statement.statement import chains2dict


def save_trust_chains(federation_context, trust_chains):
    _tc_dict = chains2dict(trust_chains)
    if federation_context.trust_chain:
        for ta, tc in _tc_dict.items():
            _ent = tc.iss_path[0]
            if _ent not in federation_context.trust_chains:
                federation_context.trust_chain = {_ent: {ta: tc}}
            else:
                federation_context.trust_chain[_ent] = {ta: tc}
    else:
        for ta, tc in _tc_dict.items():
            federation_context.trust_chain[tc.iss_path[0]] = {ta: tc}
