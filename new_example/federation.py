import logging

from entity import execute_function

#         |TA SWAMID |     | TA SEID |
#         +--------+-+     ++-----+--+
#          |       |        |     |
#          |       +--------|-+   |
#          |                | |   |
#          |     +----------+ |   |
#          |     |            |   |
#          +-----+           ++---+---+
#          | UMU |           |  LU    |
#          +--+--+           ++-----+-+
#             |               |     |
#          +--+--+          +-+-+ +-+-+
#          | OP  |          |RPA| |RPE|
#          +-----+          +---+ +---+

SWAMID_ID = "https://swamid.example.org"
SEID_ID = "https://seid.example.org"
UMU_ID = "https://umu.example.org"
LU_ID = "https://lu.example.org"
OP_ID = "https://op.example.org"
RPA_ID = "https://rpa.example.org"
RPE_ID = "https://rpe.example.org"

logger = logging.getLogger(__name__)


def federation_setup():
    ######################
    # SWAMID TRUST ANCHOR
    ######################

    logger.info("---- SWAMD Trust Anchor ----")
    kwargs = {
        "entity_id": SWAMID_ID,
        "preference": {
            "organization_name": "The SWAMID federation operator",
            "homepage_uri": "https://swamid.example.com",
            "contacts": "operations@swamid.example.com"
        }
    }
    swamid = execute_function('members.ta.main', **kwargs)
    logger.debug(f"Creating Trust Anchor: entity_id={SWAMID_ID}")
    trust_anchors = {SWAMID_ID: swamid.keyjar.export_jwks()}

    ######################
    # SEID TRUST ANCHOR
    ######################

    logger.info("---- SEID Trust Anchor ----")
    kwargs = {
        "entity_id": SEID_ID,
        "preference": {
            "organization_name": "The SEID federation operator",
            "homepage_uri": "https://seid.example.com",
            "contacts": "operations@seid.example.com"
        }
    }
    seid = execute_function('members.ta.main', **kwargs)
    logger.debug(f"Creating Trust Anchor: entity_id={SEID_ID}")
    trust_anchors[SEID_ID] = seid.keyjar.export_jwks()

    #####################
    # intermediate - UmU
    #####################
    logger.info("---- Intermediate UmU ----")

    kwargs = {
        "entity_id": UMU_ID,
        "preference": {
            "organization_name": "UmU",
            "homepage_uri": "https://umu.example.com",
            "contacts": "operations@umu.example.com"
        },
        "authority_hints": [UMU_ID],
        "trust_anchors": trust_anchors
    }
    umu = execute_function("members.intermediate.main", **kwargs)

    logger.info("--- Subordinate to both Trust Anchors ---")
    logger.debug(f"Registering '{UMU_ID}' as subordinate to '{SWAMID_ID}'")
    swamid.server.subordinate[UMU_ID] = {
        "jwks": umu.keyjar.export_jwks(),
        'authority_hints': [SWAMID_ID],
        "registration_info": {
            "entity_types": ["federation_entity"],
            "intermediate": True
        }
    }

    logger.debug(f"Registering '{UMU_ID}' as subordinate to '{SEID_ID}'")
    seid.server.subordinate[UMU_ID] = {
        "jwks": umu.keyjar.export_jwks(),
        'authority_hints': [SEID_ID],
        "registration_info": {
            "entity_types": ["federation_entity"],
            "intermediate": True
        }
    }

    ##################
    # intermediate  LU
    ##################

    logger.info("---- Intermediate LU ----")

    kwargs = {
        "entity_id": LU_ID,
        "preference": {
            "organization_name": "LU",
            "homepage_uri": "https://lu.example.com",
            "contacts": "operations@lu.example.com"
        },
        "authority_hints": [LU_ID],
        "trust_anchors": trust_anchors
    }
    lu = execute_function("members.intermediate.main", **kwargs)

    logger.info("--- Subordinate to both Trust Anchors ---")
    logger.debug(f"Registering '{LU_ID}' as subordinate to '{SWAMID_ID}'")

    swamid.server.subordinate[LU_ID] = {
        "jwks": lu.keyjar.export_jwks(),
        'authority_hints': [SWAMID_ID],
        "registration_info": {
            "entity_types": ["federation_entity"],
            "intermediate": True
        }
    }

    logger.debug(f"Registering '{LU_ID}' as subordinate to '{SEID_ID}'")

    seid.server.subordinate[LU_ID] = {
        "jwks": lu.keyjar.export_jwks(),
        'authority_hints': [SEID_ID],
        "registration_info": {
            "entity_types": ["federation_entity"],
            "intermediate": True
        }
    }

    ########################################
    # OP
    ########################################

    logger.info("---- UmU OP ----")
    logger.info("--- Subordinate to UMU ---")

    kwargs = {
        "entity_id": OP_ID,
        "preference": {
            "organization_name": "The RP",
            "homepage_uri": "https://rp.example.com",
            "contacts": "operations@rp.example.com"
        },
        "authority_hints": [UMU_ID],
        "trust_anchors": trust_anchors
    }
    umu = execute_function("members.op.main", **kwargs)

    logger.debug(f"Registering '{OP_ID}' as subordinate to '{UMU_ID}'")

    umu.server.subordinate[OP_ID] = {
        "jwks": umu.keyjar.export_jwks(),
        'authority_hints': [UMU_ID],
        "registration_info": {"entity_types": ["federation_entity", "openid_provider"]},
    }

    ########################################
    # RP - Automatic
    ########################################

    logger.info("---- RP Automatic registration ----")
    logger.info("--- Subordinate to LU ---")

    kwargs = {
        "entity_id": RPA_ID,
        "preference": {
            "organization_name": "RPA.LU",
            "homepage_uri": "https://rpa.example.com",
            "contacts": "operations@rpa.example.com"
        },
        "authority_hints": [LU_ID],
        "trust_anchors": trust_anchors
    }
    rpa = execute_function("members.rp.main", **kwargs)

    logger.debug(f"Registering '{RPA_ID}' as subordinate to '{LU_ID}'")

    lu.server.subordinate[RPA_ID] = {
        "jwks": rpa.keyjar.export_jwks(),
        'authority_hints': [LU_ID],
        "registration_info": {"entity_types": ["federation_entity", "openid_relying_party"]},
    }

    ########################################
    # RP - Explicit
    ########################################

    logger.info("---- RP Explicit registration ----")
    logger.info("---- Subordinate to LU ---")

    kwargs = {
        "entity_id": RPE_ID,
        "preference": {
            "organization_name": "RPE.LU",
            "homepage_uri": "https://rpe.example.com",
            "contacts": "operations@rpe.example.com"
        },
        "authority_hints": [LU_ID],
        "trust_anchors": trust_anchors
    }
    rpe = execute_function("members.rp.main", **kwargs)

    logger.debug(f"Registering '{RPE_ID}' as subordinate to '{LU_ID}'")

    lu.server.subordinate[RPE_ID] = {
        "jwks": rpe.keyjar.export_jwks(),
        'authority_hints': [LU_ID],
        "registration_info": {"entity_types": ["federation_entity", "openid_relying_party"]},
    }


    # ------------- return federation entities --------------

    return {
        "ta": trust_anchor,
        "im1": im1,
        "im2": im2,
        "wp": wallet_provider,
        "rp": rp,
        "pid": pid,
        "qeea": qeea
    }


if __name__ == "__main__":
    print(federation_setup())
