from abc import ABC, abstractmethod
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from http import HTTPStatus
from logging import Logger
from urllib3.util import Retry


class StairwellAPI(ABC):

    @abstractmethod
    def get_object_event_enrichment(self, hash: str) -> dict:
        pass

    @abstractmethod
    def get_hostname_event_enrichment(self, hostname: str) -> dict:
        pass

    @abstractmethod
    def get_ip_event_enrichment(self, ip: str) -> dict:
        pass


API_PATH = "labs/appapi/enrichment/v1/"

CODE_FIELD = "code"
MESSAGE_FIELD = "message"

REQUEST_TIMEOUT_SECS = 20
MAX_RETRIES = 10


class StairwellEnrichmentClient(StairwellAPI):

    # Base URL of the Stairwell service:
    base_url: str
    # Request headers for all Stairwell API requests, constructed from auth token, org ID etc:
    headers: dict[str, str]

    request_timeout: int = REQUEST_TIMEOUT_SECS
    max_retries: int = MAX_RETRIES
    logger: Logger

    def __init__(
        self,
        base_url: str,
        auth_token: str,
        organization_id: str,
        user_id: str = "",
        logger: Optional[Logger] = None,
    ):
        self.base_url = base_url
        self.headers = {
            "Authorization": auth_token,
            "Organization-Id": organization_id,
            "User-Id": user_id,
        }
        if logger != None:
            self.logger = logger

    def _get_request(self, path: str) -> dict:
        logger = self.logger
        logger.debug(path)

        session = requests.Session()
        r = Retry(
            total=self.max_retries,
            respect_retry_after_header=True,
        )
        session.mount(self.base_url, HTTPAdapter(max_retries=r))
        try:
            response = session.get(
                path, headers=self.headers, timeout=self.request_timeout
            )
        except requests.HTTPError as e:
            logger.debug(f"HTTPError: {e}")
        except requests.ReadTimeout as e:
            logger.debug(f"ReadTimeout: {e}")
        logger.debug(f"Response status_code: {response.status_code}")

        try:
            decoded_response = response.json()
        except ValueError as e:
            logger.debug(f"ValueError: {e}")

        if response.status_code == HTTPStatus.OK:
            return dict(decoded_response)
        elif response.status_code == HTTPStatus.NOT_FOUND:
            return {
                "stairwell_status": "NOT FOUND",
                "stairwell_status_details": decoded_response.get("details", {})[0],
            }
        elif response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR:
            return {
                "stairwell_status": "INTERNAL ERROR",
                "stairwell_status_details": decoded_response.get("details", {})[0],
            }
        elif response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            return {
                "stairwell_status": "TOO MANY REQUESTS",
                "stairwell_status_details": "Retries exhausted.",
            }
        else:
            # For all other status codes, report a general error along with
            # the extracted code and message if found:
            code = decoded_response.get(CODE_FIELD)
            message = decoded_response.get(MESSAGE_FIELD)
            return {
                "stairwell_status": "ERROR",
                "stairwell_status_details": f"HTTP: {response.status_code}, code: {code}, message: {message}",
            }

    def get_object_event_enrichment(self, hash: str) -> dict:
        path = f"{self.base_url}{API_PATH}object_event/{hash}"
        return self._get_request(path)

    def get_hostname_event_enrichment(self, hostname: str) -> dict:
        path = f"{self.base_url}{API_PATH}hostname_event/{hostname}"
        return self._get_request(path)

    def get_ip_event_enrichment(self, ip: str) -> dict:
        path = f"{self.base_url}{API_PATH}ip_event/{ip}"
        return self._get_request(path)
