from abc import ABC, abstractmethod
from typing import Optional
import requests
from http import HTTPStatus
from logging import Logger
import time


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
    logger: Optional[Logger]

    def __init__(
        self, base_url: str, auth_token: str, organization_id: str, user_id: str = ""
    ):
        self.base_url = base_url
        self.headers = {
            "Authorization": auth_token,
            "Organization-Id": organization_id,
            "User-Id": user_id,
        }

    def _debug(self, msg: str):
        if self.logger is None:
            return
        self.logger.debug(msg)

    def _get_request(self, path: str) -> dict:
        self._debug(path)

        num_retries = self.max_retries
        while num_retries >= 0:
            # Consume a retry. If this becomes 0, the next response should be communicated,
            # regardless of status.
            num_retries -= 1

            try:
                response = requests.get(
                    path, headers=self.headers, timeout=self.request_timeout
                )
            except requests.HTTPError as e:
                self._debug(f"HTTPError: {e}")
                continue
            except requests.ReadTimeout as e:
                self._debug(f"ReadTimeout: {e}")
                continue
            self._debug(f"Response status_code: {response.status_code}")
            try:
                decoded_response = response.json()
            except ValueError as e:
                self._debug(f"ValueError: {e}")
                continue

            if response.status_code == HTTPStatus.OK:
                return dict(decoded_response)
            elif response.status_code == HTTPStatus.NOT_FOUND:
                return {
                    "stairwell_status": "NOT FOUND",
                    "stairwell_status_details": decoded_response.get("details", {})[0],
                }
            elif response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR:
                if num_retries == 0:
                    return {
                        "stairwell_status": "INTERNAL ERROR",
                        "stairwell_status_details": decoded_response.get("details", {})[
                            0
                        ],
                    }
            elif response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                sleep_time = int(response.headers["Retry-After"])
                time.sleep(sleep_time)
            else:
                # For all other status codes, report a general error along with
                # the extracted code and message if found:
                code = decoded_response.get(CODE_FIELD)
                message = decoded_response.get(MESSAGE_FIELD)
                return {
                    "stairwell_status": "ERROR",
                    "stairwell_status_details": f"HTTP: {response.status_code}, code: {code}, message: {message}",
                }

        return {
            "stairwell_status": "TOO MANY REQUESTS",
            "stairwell_status_details": "Retries exhausted.",
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
