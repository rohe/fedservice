from typing import List
from typing import Optional

from flask import Flask
from idpyoidc.client.defaults import DEFAULT_KEY_DEFS

from fedservice.build_entity import FederationEntityBuilder
from fedservice.defaults import DEFAULT_FEDERATION_ENTITY_ENDPOINTS
from fedservice.entity import FederationEntity

TA_ENDPOINTS = DEFAULT_FEDERATION_ENTITY_ENDPOINTS.copy()


def init_entity(entity_id: str,
                authority_hints: Optional[List[str]] = None,
                trust_anchors: Optional[dict] = None,
                preference: Optional[dict] = None):
    TA = FederationEntityBuilder(
        entity_id,
        preference=preference,
        key_conf={"key_defs": DEFAULT_KEY_DEFS}
    )
    TA.add_endpoints(None, **TA_ENDPOINTS)
    ta = FederationEntity(**TA.conf)
    return ta


def init_app(entity_id: str,
             authority_hints: Optional[List[str]] = None,
             trust_anchors: Optional[dict] = None,
             preference: Optional[dict] = None,
             name=None, **kwargs) -> Flask:
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)

    try:
        from .views import intermediate
    except ImportError:
        from views import intermediate

    app.register_blueprint(intermediate)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.server = init_entity(entity_id,
                             authority_hints,
                             trust_anchors,
                             preference)

    return app
