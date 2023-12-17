import logging
from typing import Callable
from typing import Optional

from idpyoidc.exception import MissingPage

from fedservice.entity.function import Function
from fedservice.entity.utils import get_federation_entity
from fedservice.exception import FailedInformationRetrieval

logger = logging.getLogger(__name__)


class MetadataVerifier(Function):

    # content_type = 'application/jose'

    def __init__(self, upstream_get: Callable, metadata_verifier_id: Optional[str] = ""):
        Function.__init__(self, upstream_get)
        self.metadata_verifier_id = metadata_verifier_id or self.upstream_get("attribute",
                                                                              "entity_id")

    def __call__(self, registration_response: str):
        """

        :param url: Target URL
        :param httpc_args: Arguments for the HTTP call.
        :return: Service response (OK or error message)
        """
        _fed = get_federation_entity(self)
        _serv = _fed.get_service("metadata_verification")

        _collector = _fed.get_function('trust_chain_collector')
        _metadata = _collector.get_metadata(self.metadata_verifier_id)
        endpoint = _metadata["federation_entity"]["federation_metadata_verification_endpoint"]

        _res = _serv.get_request_parameters(
            request_args={"registration_response": registration_response},
            endpoint=endpoint)

        kwargs = _res
        _url = _res["url"]
        _keyjar = self.upstream_get('attribute', 'keyjar')
        _res.update(_keyjar.httpc_params)
        try:
            response = self.upstream_get('attribute', 'httpc')(**kwargs)
        except ConnectionError:
            logger.error(f'Could not connect to {_url}')
            raise

        if response.status_code == 200:
            # Might be two different responses: text or jose
            _content_type = response.headers['Content-Type'].split(',')
            _content_type = [c.strip() for c in _content_type]
            if "text/plain" in _content_type or "text/html" in _content_type:
                pass
            elif "application/jose" in _content_type:
                pass
            else:
                logger.warning(f"Wrong Content-Type: {response.headers['Content-Type']}")
            return response.text
        elif response.status_code == 404:
            raise MissingPage(f"No such page: '{_url}'")
        else:
            raise FailedInformationRetrieval()
