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

from datetime import datetime
from inspect import signature
from logging import Logger
from stairwelllib.client import StairwellAPI
from stairwelllib.stairwell_appapi_client import (
    ApiException,
    IPEventEnrichment,
    ObjectEventEnrichment,
    HostnameEventEnrichment,
    Opinion,
    Comment,
    ObjectSignature,
)
from typing import Optional, List

SPLUNK_IP_ADDRESS_ATTRIBUTE = "ipaddress"
SPLUNK_OBJECT_ATTRIBUTE = "object"
SPLUNK_HOSTNAME_ATTRIBUTE = "hostname"


def opinions_to_dicts(opinions: Optional[List[Opinion]]) -> List[dict]:
    if opinions == None:
        return []
    return [opinion.to_dict() for opinion in opinions]


def comments_to_dicts(comments: Optional[List[Comment]]) -> List[dict]:
    if comments == None:
        return []
    return [comment.to_dict() for comment in comments]


def search_stairwell_ip_addresses_api(
    client: StairwellAPI, logger: Logger, ip_value: str
) -> dict:
    """Calls Stairwell API with an IP Address lookup"""
    logger.debug("Entered search_stairwell_ip_addresses_api")
    record = {}

    # Set non-response fields
    record["stairwell_event_type"] = SPLUNK_IP_ADDRESS_ATTRIBUTE
    record["stairwell_resource_type"] = SPLUNK_IP_ADDRESS_ATTRIBUTE
    record["stairwell_resource_id"] = ip_value

    response: IPEventEnrichment
    try:
        response = client.get_ip_event_enrichment(ip_value)
    except ApiException as e:
        return {"stairwell_error": str(e), "stairwell_status": str(e.status)}

    # Set common fields
    record["stairwell_opinions_most_recent"] = opinions_to_dicts(
        response.opinions_most_recent
    )
    record["stairwell_comments_most_recent"] = comments_to_dicts(
        response.comments_most_recent
    )

    # Set IP-specific fields
    record["stairwell_uninteresting_addr"] = response.uninteresting_addr

    return record


def signature_to_dict(signature: ObjectSignature) -> dict:
    """Converts an ObjectSignature to a dict representation, with relevant
    datetimes formatted via .isoformat()."""
    d = signature.to_dict()
    certs = d.get("x509Certificates")
    if certs == None:
        return d
    for cert in certs:
        early_time = cert.get("earliestValidTime")
        if isinstance(early_time, datetime):
            cert["earliestValidTime"] = early_time.isoformat()
        late_time = cert["latestValidTime"]
        if isinstance(late_time, datetime):
            cert["latestValidTime"] = late_time.isoformat()
    return d


def search_stairwell_object_api(
    client: StairwellAPI, logger: Logger, object_value: str
) -> dict:
    """Calls Stairwell API with an Object lookup"""
    logger.debug("Entered search_stairwell_object_api")
    record = {}

    # Set non-response resources
    record["stairwell_event_type"] = SPLUNK_OBJECT_ATTRIBUTE
    record["stairwell_resource_type"] = SPLUNK_OBJECT_ATTRIBUTE
    record["stairwell_resource_id"] = object_value

    response: ObjectEventEnrichment
    try:
        response = client.get_object_event_enrichment(object_value)
    except ApiException as e:
        return {"stairwell_error": str(e), "stairwell_status": str(e.status)}

    # Set common fields
    record["stairwell_opinions_most_recent"] = opinions_to_dicts(
        response.opinions_most_recent
    )
    record["stairwell_comments_most_recent"] = comments_to_dicts(
        response.comments_most_recent
    )

    # Set object-specific fields
    record["stairwell_object_md5"] = response.file_hash_md5
    record["stairwell_object_sha1"] = response.file_hash_sha1
    record["stairwell_object_sha256"] = response.file_hash_sha256
    record["stairwell_object_size"] = response.file_size
    if response.sightings_first != None:
        record["stairwell_object_first_seen_time"] = (
            response.sightings_first.isoformat()
        )
    record["stairwell_object_mal_eval"] = response.verdict_maleval_labels
    record["stairwell_object_mal_eval_probability"] = (
        response.verdict_maleval_malicious_probability
    )
    record["stairwell_object_yara_rule_matches"] = response.verdict_yara_rule_matches
    record["stairwell_object_network_indicators_ip_addresses"] = (
        response.indicators_ips_likely
    )
    record["stairwell_object_network_indicators_hostnames"] = (
        response.indicators_hostnames_likely
    )
    record["stairwell_object_network_indicators_hostnames_private"] = (
        response.indicators_hostnames_private
    )
    record["stairwell_object_magic"] = response.file_magic
    record["stairwell_object_mime_type"] = response.file_mime_type
    record["stairwell_object_entropy"] = response.file_entropy
    record["stairwell_object_imp_hash"] = response.file_hash_imphash
    record["stairwell_object_sorted_imp_hash"] = response.file_hash_sorted_imphash
    record["stairwell_object_tlsh"] = response.file_hash_tlsh

    if response.signature != None:
        record["stairwell_object_signature"] = signature_to_dict(response.signature)

    if response.sightings_prevalence != None:
        record["stairwell_object_prevalence"] = [
            p.to_dict() for p in response.sightings_prevalence
        ]

    record["stairwell_object_is_well_known"] = response.verdict_is_well_known
    record["stairwell_object_variants"] = response.variants
    record["stairwell_ai_assessment"] = response.summary_ai
    record["stairwell_object_run_to_ground"] = response.summary_rtg

    return record


def hostname_record_to_dict(record) -> dict:
    """Converts a hostname record to a dict representation, with relevant
    datetimes formatted via .isoformat(). The provided record must have the
    method to_dict()."""
    d = record.to_dict()
    t = d["lookupTime"]
    if isinstance(t, datetime):
        d["lookupTime"] = t.isoformat()
    return d


def search_stairwell_hostname_api(
    client: StairwellAPI, logger: Logger, hostname_value: str
) -> dict:
    """Calls Stairwell API with a hostname lookup"""
    logger.debug("Entered search_stairwell_hostname_api")
    record = {}

    # Set non-response resources
    record["stairwell_event_type"] = SPLUNK_HOSTNAME_ATTRIBUTE
    record["stairwell_resource_type"] = SPLUNK_HOSTNAME_ATTRIBUTE
    record["stairwell_resource_id"] = hostname_value

    response: HostnameEventEnrichment
    try:
        response = client.get_hostname_event_enrichment(hostname_value)
    except ApiException as e:
        return {"stairwell_error": str(e), "stairwell_status": str(e.status)}

    # Set common fields
    record["stairwell_opinions_most_recent"] = opinions_to_dicts(
        response.opinions_most_recent
    )
    record["stairwell_comments_most_recent"] = comments_to_dicts(
        response.comments_most_recent
    )
    # Set hostname-specific fields
    if response.lookup_a_records != None:
        record["stairwell_hostname_a_records"] = [
            hostname_record_to_dict(r) for r in response.lookup_a_records
        ]
    if response.lookup_aaaa_records != None:
        record["stairwell_hostname_aaaa_records"] = [
            hostname_record_to_dict(r) for r in response.lookup_aaaa_records
        ]
    if response.lookup_mx_records != None:
        record["stairwell_hostname_mx_records"] = [
            hostname_record_to_dict(r) for r in response.lookup_mx_records
        ]
    record["stairwell_hostname"] = hostname_value

    return record
