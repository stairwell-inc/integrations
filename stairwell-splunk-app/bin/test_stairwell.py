from stairwell import Stairwell
from stairwelllib.client import StairwellAPI
from stairwelllib.swlogging import fake_logger
import stairwelllib.stairwellapi

class FakeStairwellClient(StairwellAPI):

    hash_data: dict[str, dict[str, str]] = {}
    hostname_data: dict[str, dict[str, str]] = {}
    ip_data: dict[str, dict[str, str]] = {}
    
    def get_object_event_enrichment(self, hash: str) -> dict[str, str]:
        res = self.hash_data.get(hash)
        if res == None:
            return {}
        return res
    
    def get_hostname_event_enrichment(self, hostname: str) -> dict[str, str]:
        res = self.hostname_data.get(hostname)
        if res == None:
            return {}
        return res

    def get_ip_event_enrichment(self, ip: str) -> dict[str, str]:
        res = self.ip_data.get(ip)
        if res == None:
            return {}
        return res

def test_search_stairwell_hostname_api():
    logger = fake_logger()

    fake_client = FakeStairwellClient()
    fake_client.hostname_data["downloadmoreram.com"] = {
        "opinionsMostRecent": "blah blah blah blah blah"
    }
    
    command = Stairwell()
    command.client = fake_client


    res = stairwelllib.stairwellapi.search_stairwell_ip_addresses_api(command, logger, "downloadmoreram.com")
    print(res)
    assert res == "ahhhhh"
    # assert client.get_hostname_event_enrichment("downloadmoreram.com") == None