from abc import ABC, abstractmethod
from typing import Optional
from logging import Logger
from stairwell_appapi_client import (
    ApiClient,
    ObjectEventEnrichment,
    IPEventEnrichment,
    HostnameEventEnrichment,
    Enrichmentv1Api,
    Configuration,
)


class StairwellAPI(ABC):
    """StairwellAPI performs stairwell_appapi_client requests."""

    @abstractmethod
    def get_object_event_enrichment(self, hash: str) -> ObjectEventEnrichment:
        """Makes a request to the object enrichment API with the provided hash. May throw an
        ApiException if an error is encountered."""
        pass

    @abstractmethod
    def get_hostname_event_enrichment(self, hostname: str) -> HostnameEventEnrichment:
        """Makes a request to the hostname enrichment API with the provided hostname. May throw an
        ApiException if an error is encountered."""
        pass

    @abstractmethod
    def get_ip_event_enrichment(self, ip: str) -> IPEventEnrichment:
        """Makes a request to the IP address enrichment API with the provided IP address. May throw
        an ApiException if an error is encountered."""
        pass


class StairwellEnrichmentClient(StairwellAPI):
    """StairwellEnrichmentClient interacts with the Stairwell enrichment API, using the configured
    base URL, retries and timeout values. It also performs optional debug logging.
    """

    # OpenAPI-generated REST client for the Enrichment service:
    client: Enrichmentv1Api

    # Logger to output debug messages through (optional).
    logger: Logger

    # Base URL of the Stairwell service:
    base_url: str

    def __init__(
        self,
        base_url: str,
        auth_token: str,
        organization_id: str,
        user_id: str = "",
        logger: Optional[Logger] = None,
    ):
        client = ApiClient(
            configuration=Configuration(
                host=base_url,
                api_key={"AuthToken": auth_token},
            ),
            header_name="Organization-Id",
            header_value=organization_id,
        )
        client.set_default_header("User-Id", user_id)
        self.client = Enrichmentv1Api(client)

        if logger:
            self.logger = logger

    def get_object_event_enrichment(self, hash: str) -> ObjectEventEnrichment:
        self.logger.debug(f"req: get_object_event_enrichment({hash})")
        res = self.client.enrichmentv1_get_object_event_enrichment_v1(
            name=hash,
        )
        return res

    def get_hostname_event_enrichment(self, hostname: str) -> HostnameEventEnrichment:
        self.logger.debug(f"req: get_hostname_event_enrichment({hostname})")
        return self.client.enrichmentv1_get_hostname_event_enrichment_v1(
            name=hostname,
        )

    def get_ip_event_enrichment(self, ip: str) -> IPEventEnrichment:
        self.logger.debug(f"req: get_ip_event_enrichment({ip})")
        return self.client.enrichmentv1_get_ip_event_enrichment_v1(
            name=ip,
        )
