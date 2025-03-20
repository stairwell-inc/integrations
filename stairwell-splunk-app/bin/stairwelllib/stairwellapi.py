# Copyright (C) 2025 Stairwell Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License found in the LICENSE file in the root directory of
# this source tree. Also found at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Functions for translating Stairwell API responses into Splunk records."""

SPLUNK_IP_ADDRESS_ATTRIBUTE = "ipaddress"
SPLUNK_OBJECT_ATTRIBUTE = "object"
SPLUNK_HOSTNAME_ATTRIBUTE = "hostname"


# TODO: Generate from API definition. Maps from fields in the JSON Stairwell API
# response to the column names of output Splunk records.
common_response_to_record_field_mapping = {
    # Error / status resources
    "stairwell_status": "stairwell_status",
    "stairwell_status_details": "stairwell_status_details",
    "stairwell_error": "stairwell_error",
    # Shared fields
    "opinionsMostRecent": "stairwell_opinions_most_recent",
    "commentsMostRecent": "stairwell_comments_most_recent",
    "summaryAi": "stairwell_ai_assessment",
}

ip_response_to_record_field_mapping = {
    "uninterestingAddr": "stairwell_uninteresting_addr",
    "associatedHostnames": "stairwell_associated_hostnames",
}

hash_response_to_record_field_mapping = {
    "fileHashMd5": "stairwell_object_md5",
    "fileHashSha1": "stairwell_object_sha1",
    "fileHashSha256": "stairwell_object_sha256",
    "fileSize": "stairwell_object_size",
    "sightingsFirst": "stairwell_object_first_seen_time",
    "verdictMalevalLabels": "stairwell_object_mal_eval",
    "verdictMalevalMaliciousProbability": "stairwell_object_mal_eval_probability",
    "verdictYaraRuleMatches": "stairwell_object_yara_rule_matches",
    "indicatorsIpsLikely": "stairwell_object_network_indicators_ip_addresses",
    "indicatorsHostnamesLikely": "stairwell_object_network_indicators_hostnames",
    "indicatorsHostnamesPrivate": "stairwell_object_network_indicators_hostnames_private",
    "fileMagic": "stairwell_object_magic",
    "fileMimeType": "stairwell_object_mime_type",
    "fileEntropy": "stairwell_object_entropy",
    "fileHashImphash": "stairwell_object_imp_hash",
    "fileHashSortedImphash": "stairwell_object_sorted_imp_hash",
    "fileHashTlsh": "stairwell_object_tlsh",
    "signature": "stairwell_object_signature",
    "sightingsPrevalence": "stairwell_object_prevalence",
    "verdictIsWellKnown": "stairwell_object_is_well_known",
    "variants": "stairwell_object_variants",
    "summaryRtg": "stairwell_object_run_to_ground",
}

hostname_response_to_record_field_mapping = {
    "lookupARecords": "stairwell_hostname_a_records",
    "lookupAaaaRecords": "stairwell_hostname_aaaa_records",
    "lookupMxRecords": "stairwell_hostname_mx_records",
}


def translate_response_fields(response, mappings):
    """From an input response dict, extracts all values matching keys in the
    response to record field mappings and sets them in a record output dict.
    """
    record = {}
    for mapping in mappings:
        for responseKey, recordKey in mapping.items():
            v = response.get(responseKey)
            if v != None:
                record[recordKey] = v
    return record


def search_stairwell_ip_addresses_api(search_command, logger, ip_value):
    """Calls Stairwell API with an IP Address lookup"""
    logger.debug("Entered search_stairwell_ip_addresses_api")

    response = search_command.client.get_ip_event_enrichment(ip_value)
    record = translate_response_fields(
        response,
        [common_response_to_record_field_mapping, ip_response_to_record_field_mapping],
    )

    # Set non-response resources
    record["stairwell_event_type"] = SPLUNK_IP_ADDRESS_ATTRIBUTE
    record["stairwell_resource_type"] = SPLUNK_IP_ADDRESS_ATTRIBUTE
    record["stairwell_resource_id"] = ip_value

    return record


def search_stairwell_object_api(search_command, logger, object_value):
    """Calls Stairwell API with an Object lookup"""
    logger.debug("Entered search_stairwell_object_api")

    response = search_command.client.get_object_event_enrichment(object_value)
    record = translate_response_fields(
        response,
        [
            common_response_to_record_field_mapping,
            hash_response_to_record_field_mapping,
        ],
    )
    # Set non-response resources
    record["stairwell_event_type"] = SPLUNK_OBJECT_ATTRIBUTE
    record["stairwell_resource_type"] = SPLUNK_OBJECT_ATTRIBUTE
    record["stairwell_resource_id"] = object_value

    return record


def search_stairwell_hostname_api(search_command, logger, hostname_value):
    """Calls Stairwell API with a hostname lookup"""
    logger.debug("Entered search_stairwell_hostname_api")

    response = search_command.client.get_hostname_event_enrichment(hostname_value)
    record = translate_response_fields(
        response,
        [
            common_response_to_record_field_mapping,
            hostname_response_to_record_field_mapping,
        ],
    )

    # Set non-response resources
    record["stairwell_event_type"] = SPLUNK_HOSTNAME_ATTRIBUTE
    record["stairwell_resource_type"] = SPLUNK_HOSTNAME_ATTRIBUTE
    record["stairwell_resource_id"] = hostname_value
    record["stairwell_hostname"] = hostname_value

    return record
