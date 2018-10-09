import json
import os
from urllib.parse import urlparse

from cryptojwt.key_jar import KeyJar

from fedservice.entity_statement.create import create_entity_statement


def superiors(node):
    return [o for o in os.listdir(node) if os.path.isdir(os.path.join(node, o))]


def collect_trust_roots(node):
    dirs = [os.path.join(node, o) for o in os.listdir(node)
            if os.path.isdir(os.path.join(node, o))]

    if dirs:
        res = []
        for d in dirs:
            sups = collect_authorities(d)
            if not sups:
                (head, tail) = os.path.split(d)
                res.append(tail)
            else:
                res.extend(sups)
        return res
    else:
        return None


def collect_authorities(node):
    dirs = [os.path.join(node, o) for o in os.listdir(node)
            if os.path.isdir(os.path.join(node, o))]

    if dirs:
        res = {}
        for d in dirs:
            trust_roots = collect_trust_roots(d)
            (head, tail) = os.path.split(d)
            if trust_roots:
                res[tail] = trust_roots
            else:
                res[tail] = [tail]
        return res
    else:
        return None


def get_dir(eid, root_dir):
    p = urlparse(eid)
    _dir = p.netloc
    return os.path.join(root_dir, _dir)


def main(rootdir, iss, sub):
    if sub != iss:
        sub_dir = get_dir(sub, rootdir)
        iss_dir = get_dir(iss, sub_dir)
    else:
        iss_dir = get_dir(iss, rootdir)
        sub_dir = iss_dir

    kj = KeyJar()
    kj.import_jwks_as_json(
        open(os.path.join(iss_dir, 'jwks.json')).read(), iss)

    if sub != iss:
        kj.import_jwks_as_json(
            open(os.path.join(sub_dir, 'jwks.json')).read(), sub)

    msg = json.loads(
        open(os.path.join(iss_dir, 'metadata.json')).read())

    authority_hints = collect_authorities(os.path.join(iss_dir))
    if authority_hints:
        _jwt = create_entity_statement(msg, iss, sub, kj, authority_hints)
    else:
        _jwt = create_entity_statement(msg, iss, sub, kj)

    return _jwt


def do_superior(root_dir, eid):
    _dir = get_dir(eid, root_dir)
    res = {}
    for s in superiors(_dir):
        intermediate = "https://{}".format(s)
        res["({}, {})".format(eid, intermediate)] = main(root_dir, intermediate,
                                                         eid)
        res.update(do_superior(_dir, intermediate))
    return res


if __name__ == "__main__":
    eid = 'https://op.example.com'
    root_dir = os.path.dirname(os.path.abspath(__file__))

    res = {"({}, {})".format(eid, eid): main(root_dir, eid, eid)}

    res.update(do_superior(root_dir, eid))

    print(json.dumps(res, sort_keys=True, indent=4))
