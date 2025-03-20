from stairwell import Stairwell
from stairwelllib.client import StairwellAPI
from stairwelllib.swlogging import fake_logger
import stairwelllib.stairwellapi


class FakeStairwellClient(StairwellAPI):

    hash_data: dict[str, dict] = {}
    hostname_data: dict[str, dict] = {}
    ip_data: dict[str, dict] = {}

    def get_object_event_enrichment(self, hash: str) -> dict:
        res = self.hash_data.get(hash)
        if res == None:
            return {}
        return res

    def get_hostname_event_enrichment(self, hostname: str) -> dict:
        res = self.hostname_data.get(hostname)
        if res == None:
            return {}
        return res

    def get_ip_event_enrichment(self, ip: str) -> dict:
        res = self.ip_data.get(ip)
        if res == None:
            return {}
        return res


def test_search_stairwell_hostname_api():
    logger = fake_logger()

    fake_client = FakeStairwellClient()
    fake_client.hostname_data["downloadmoreram.com"] = {
        "opinionsMostRecent": [
            {
                "verdict": "MALICIOUS",
                "timestamp": "2025-02-20T18:48:32.867Z",
            },
        ],
        "commentsMostRecent": ["Wow", "ok"],
        "summaryAi": "blah blah blah",
        "lookupARecords": [
            {
                "type": "A",
                "host": ".com.downloadmoreram",
                "status": "NOERROR",
                "answer": "10.100.100.100",
                "time": "2020-01-01T01:10:10Z",
            },
        ],
        "lookupAaaaRecords": [
            {
                "type": "AAAA",
                "host": ".com.downloadmoreram",
                "status": "NOERROR",
                "answer": "1000:f0b0:1000:c00::00",
                "time": "2020-01-01T01:10:10Z",
            },
        ],
        "lookupMxRecords": [
            {
                "type": "MX",
                "host": ".com.downloadmoreram",
                "status": "NOERROR",
                "answer": ".com.downloadmoreram.smtp",
                "time": "2020-01-01T01:10:10Z",
            },
        ],
    }

    command = Stairwell()
    command.client = fake_client

    res = stairwelllib.stairwellapi.search_stairwell_hostname_api(
        command, logger, "downloadmoreram.com"
    )

    assert res.get("stairwell_comments_most_recent") == ["Wow", "ok"]
    assert (
        res.get("stairwell_opinions_most_recent", [{}])[0].get("verdict") == "MALICIOUS"
    )
    assert res.get("stairwell_ai_assessment") == "blah blah blah"
    assert (
        res.get("stairwell_hostname_a_records", [{}])[0].get("answer")
        == "10.100.100.100"
    )
    assert (
        res.get("stairwell_hostname_aaaa_records", [{}])[0].get("answer")
        == "1000:f0b0:1000:c00::00"
    )
    assert (
        res.get("stairwell_hostname_mx_records", [{}])[0].get("answer")
        == ".com.downloadmoreram.smtp"
    )
