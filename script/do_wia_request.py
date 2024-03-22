#! /usr/bin/env python3
import json
import sys

from idpyoidc.util import rndstr

from fedservice.utils import make_federation_combo

# Arguments
trust_anchors_file = sys.argv[1]
wallet_provider_id = sys.argv[2]

# Create simple entity
server = make_federation_combo(
    entity_id="https://127.0.0.1:6666",
    httpc_params={"verify": False},
    trust_anchors=json.loads(open(trust_anchors_file).read()),
    key_config={
        "key_defs": [
            {
                "type": "EC",
                "crv": "P-256",
                "use": [
                    "sig"
                ]
            }
        ]
    },
    entity_type={
        "wallet": {
            "class": "openid4v.client.Wallet",
            "kwargs": {
                "config": {
                    "services": {
                        "wallet_instance_attestation": {
                            "class": "openid4v.client.wallet_instance_attestation.WalletInstanceAttestation"
                        },
                        "app_attestation": {
                            "class": "openid4v.client.app_attestation_service.AppAttestationService"
                        }
                    },
                    "httpc_params": {
                        "verify": False
                    }
                },
                "key_conf": {
                    "key_defs": [
                        {
                            "type": "EC",
                            "crv": "P-256",
                            "use": [
                                "sig"
                            ]
                        }
                    ]
                }
            }
        }
    }
)

trust_chains = server["federation_entity"].get_trust_chains(wallet_provider_id)
trust_chain = trust_chains[0]

wallet_entity = server["wallet"]
# WIA request
_service = wallet_entity.get_service("wallet_instance_attestation")
_service.wallet_provider_id = wallet_provider_id

request_args = {"aud": wallet_provider_id, "nonce": "__ignore__"}

# This is where the request is actually sent
resp = wallet_entity.do_request(
    "wallet_instance_attestation",
    request_args=request_args,
    endpoint=trust_chain.metadata['wallet_provider']['token_endpoint'])

print(resp)
