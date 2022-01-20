import logging
from typing import Dict

from oidcop.endpoint import Endpoint

LOGGER = logging.getLogger(__name__)


def add_support(endpoint: Dict[str, Endpoint], **kwargs):
    _endpoint = endpoint.get("list")
    _endpoint.server_get("context").args["intermediate"] = kwargs
