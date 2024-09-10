#!/usr/bin/env python3
import json

from idpyoidc.storage.abfile import AbstractFileSystem

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-s', "--source")
    parser.add_argument('-t', "--target")
    args = parser.parse_args()

    if not args.target or not args.source:
        print("Need both target and source")

    _ab_dict = AbstractFileSystem(fdir=args.target,
                                  key_conv="idpyoidc.util.Base64",
                                  value_conv="idpyoidc.util.JSON")
    with open(args.source, "r") as fp:
        _info = json.loads(fp.read())

    for key, val in _info.items():
        _ab_dict[key] = val

