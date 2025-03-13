from abc import ABC, abstractmethod
import requests
from http import HTTPStatus
import time


class StairwellAPI(ABC):

    @abstractmethod
    def get_object_event_enrichment(self, hash: str) -> dict[str, str]:
        pass
    
    @abstractmethod    
    def get_hostname_event_enrichment(self, hostname: str) -> dict[str, str]:
        pass

    @abstractmethod
    def get_ip_event_enrichment(self, ip: str) -> dict[str, str]:
        pass

API_PATH = "labs/appapi/enrichment/v1/"

class StairwellEnrichmentClient(StairwellAPI):

    # Base URL of the Stairwell service:
    base_url: str
    # Request headers for all Stairwell API requests, constructed from auth token, org ID etc:
    headers: dict[str, str]

    request_timeout: int = 20
    max_retries: int = 10
    logger = None # type: ignore

    def __init__(self, base_url: str, auth_token: str, organization_id: str, user_id: str = ""):
        self.base_url = base_url
        self.headers = {
            "Authorization": auth_token,
            "Organization-Id": organization_id,
            "User-Id": user_id,
        }

    def _debug(self, msg: str):
        if self.logger is None:
            return
        self.logger.debug(msg) # type: ignore

    def _get_request(self, path: str) -> dict[str, str]:
        self._debug(path)

        num_retries = self.max_retries
        while num_retries >= 0:
            response = requests.get(path, headers=self.headers, timeout=self.request_timeout)
            self._debug(f"Response status_code: {response.status_code}")
            decoded_response = response.json()

            if response.status_code == HTTPStatus.NOT_FOUND:
                return {
                    "stairwell_status": "NOT FOUND",
                    "stairwell_status_details": decoded_response.get("details", {})[0]
                }
            
            if response.status_code == HTTPStatus.INTERNAL_SERVER_ERROR:
                if num_retries == 0:
                    return {
                        "stairwell_status": "INTERNAL ERROR",
                        "stairwell_status_details": decoded_response.get("details", {})[0]
                    }
                
            if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:                    
                sleep_time = int(response.headers["Retry-After"])
                time.sleep(sleep_time)

            if response.status_code == HTTPStatus.OK:
                return dict(decoded_response)

            # Consume a retry. If this becomes 0, the next response should be communicated, 
            # regardless of status.
            num_retries -= 1

        return {
            "stairwell_status": "TOO MANY REQUESTS",
        }

    def get_object_event_enrichment(self, hash: str) -> dict[str, str]:
        path = f"{self.base_url}{API_PATH}object_event/{hash}"
        return self._get_request(path)

    def get_hostname_event_enrichment(self, hostname: str):
        path = f"{self.base_url}{API_PATH}hostname_event/{hostname}"
        return self._get_request(path)

    def get_ip_event_enrichment(self, ip: str):
        path = f"{self.base_url}{API_PATH}ip_event/{ip}"
        return self._get_request(path)
