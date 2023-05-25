import json

from cryptojwt import KeyBundle
from cryptojwt.jws.jws import factory
from fedservice.entity.function import apply_policies

from fedservice.entity.function import verify_trust_chains

from fedservice.entity.function import collect_trust_chains
from idpyoidc.node import Unit
from requests import request

from fedservice.build_entity import FederationEntityBuilder
from fedservice.entity import FederationEntity
from fedservice.entity.function import verify_self_signed_signature

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


def create_entity(ta_defs: dict) -> Unit:
    _ent = FederationEntityBuilder(
        'https://127.0.0.1',
        key_conf={"key_defs": KEYDEFS},
        authority_hints=ta_defs.keys()
    )
    _ent.add_services()
    _ent.add_functions()

    _entity = FederationEntity(**_ent.conf)
    _entity.keyjar.httpc_params = {'verify': False}
    for ta, keys in ta_defs.items():
        _entity.function.trust_chain_collector.add_trust_anchor(ta, keys)
    return _entity


def get_trust_anchors(anchors: str) -> dict:
    res = {}
    _names = json.loads(open(args.anchors).read())  # short name vs entity_id
    for name, eid in _names.items():
        _keys = json.loads(open(f'public/{name}/jwks.json').read())
        res[eid] = _keys
    return res


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', "--insecure", action='store_true')
    parser.add_argument('-a', "--anchors")
    parser.add_argument('-i', '--iss')
    parser.add_argument('-s', '--sub')
    parser.add_argument('-t', '--tenant')
    parser.add_argument('entity_id')
    parser.add_argument('operation')

    args = parser.parse_args()

    _entity = create_entity(get_trust_anchors(args.anchors))
    _entity.client.get_context().issuer = args.entity_id

    _query = {}
    _op = None
    if args.operation == 'list':
        # Need to get the entity configuration first
        _collector = _entity.function.trust_chain_collector
        _res = _collector.get_entity_configuration(args.entity_id)
        ec = verify_self_signed_signature(_res)
        # Now for the question
        _op = _entity.get_service('list')
        _query = _op.get_request_parameters(
            endpoint=ec['metadata']['federation_entity']['federation_list_endpoint'])
        res = request(verify=False, **_query)
        print(res.text)
    elif args.operation == 'config':
        _collector = _entity.function.trust_chain_collector
        _res = _collector.get_entity_configuration(args.entity_id)
        ec = verify_self_signed_signature(_res)
        print(json.dumps(ec, sort_keys=True, indent=2))
    elif args.operation == 'fetch':
        # Need to get the entity configuration first
        _collector = _entity.function.trust_chain_collector
        _res = _collector.get_entity_configuration(args.entity_id)
        ec = verify_self_signed_signature(_res)
        # Add keys

        _kb = KeyBundle(keys=ec['jwks']['keys'])
        _entity.keyjar.add_kb(ec['sub'], _kb)

        #
        _entity_statement = _collector.get_entity_statement(
            fetch_endpoint=ec['metadata']['federation_entity']['federation_fetch_endpoint'],
            issuer=args.entity_id,
            subject=args.sub
        )

        _jwt = factory(_entity_statement)
        if _jwt:
            keys = _entity.keyjar.get_jwt_verify_keys(_jwt.jwt)
            if keys is []:
                print(f'No keys matching: {_jwt.jwt.headers}')
            else:
                _res = _jwt.verify_compact(keys=keys)
                print(json.dumps(_res, sort_keys=True, indent=2))
        else:
            print('Not a proper JWS')
    elif args.operation == 'trust_chains':
        chains, signed_entity_configuration = collect_trust_chains(_entity, args.entity_id)
        print(f'Number of chains: {len(chains)}')
        trust_chains = verify_trust_chains(_entity, chains, signed_entity_configuration)
        print(f'Number of trusted chains: {len(chains)}')
        _res = apply_policies(_entity, trust_chains)
        # calculated the metadata per chain
        for item in _res:
            print(f'Anchor: {item.anchor}')
            _meta = f'metadata: {item.metadata}'
            print(json.dumps(_meta, sort_keys=True, indent=2))
        print('Done')