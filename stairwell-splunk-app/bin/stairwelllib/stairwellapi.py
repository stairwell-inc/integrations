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

# Functions for use with the Stairwell API

import json
import requests
import time
import urllib
from urllib.error import HTTPError

SECRET_REALM = 'stairwell_realm'
SECRET_NAME = 'admin'

# The number of attempts to send API request if endpoint is busy
MAX_RETRIES = 10

ROOT_API_URL = "https://app.stairwell.com/v1/"
METADATA_PATH = "/metadata"
OBJECTS_API = "objects/"
IP_API = "ipAddresses/"
HOSTNAME_API = "hostnames/"
DEV_API_URL = "https://app.stairwell.dev/labs/appapi/enrichment/v1/object_event/"
SPLUNK_IP_ADDRESS_ATTRIBUTE = "ipaddress"
SPLUNK_OBJECT_ATTRIBUTE = "object"
SPLUNK_HOSTNAME_ATTRIBUTE = "hostname"

CODE_FIELD = 'code'
MESSAGE_FIELD = 'message'


def get_encrypted_token(search_command):
    secrets = search_command.service.storage_passwords
    return next(secret for secret in secrets if (secret.realm == SECRET_REALM and secret.username == SECRET_NAME)).clear_password


def get_outbound_headers(search_command):
    secrets = get_encrypted_token(search_command)
    secrets_json = json.loads(secrets)
    auth_token = secrets_json["password"]
    organization_id = secrets_json["organizationId"]
    user_id = secrets_json["userId"]
    headers = {
        "Authorization": f"{auth_token}",
        "Organization-Id": f"{organization_id}",
        "User-Id": f"{user_id}",
        "accept": "application/json"
    }
    return headers


def search_stairwell_ip_addresses_api(search_command, logger, ip_value):
    logger.debug("Entered search_stairwell_ip_addresses_api")

    api_url = f"{ROOT_API_URL}{IP_API}{ip_value}{METADATA_PATH}"
    response_dictionary = {}

    try:
        status, response = get_from_api(search_command, logger, api_url)
    except Exception as e:
        response_dictionary["stairwell_error"] = f"Stairwell API error: {e}"
        return response_dictionary

    # Set Common Resources
    response_dictionary["stairwell_event_type"] = SPLUNK_IP_ADDRESS_ATTRIBUTE
    response_dictionary["stairwell_resource_type"] = SPLUNK_IP_ADDRESS_ATTRIBUTE
    response_dictionary["stairwell_resource_id"] = ip_value
    # TODO: waiting for implementation in the API, before these can be completed.
    # response_dictionary["stairwell_comments"]
    # response_dictionary["stairwell_tags"]
    # response_dictionary["stairwell_opinions"]
    # response_dictionary["stairwell_ai_assessment"]

    # Set IP Address specific resources
    response_dictionary["stairwell_ip_address"] = response.get("ipaddress")
    response_dictionary["stairwell_event_type"] = SPLUNK_IP_ADDRESS_ATTRIBUTE
    response_dictionary["stairwell_tags"] = response.get("tags", [])
    return response_dictionary


def search_stairwell_object_api(search_command, logger, object_value):
    logger.debug("Entered search_stairwell_object_api")

    api_url = f"{DEV_API_URL}{object_value}"
    response_dictionary = {}

    try:
        status, response = get_from_api(search_command, logger, api_url)
        if status != 200:
            if CODE_FIELD in response and MESSAGE_FIELD in response:
                code = response.get(CODE_FIELD)
                message = response.get(MESSAGE_FIELD)
                response_dictionary["stairwell_status"] = f"Error: {code}, Reason: {message}"
            return response_dictionary

    except Exception as e:
        response_dictionary["stairwell_status"] = f"Stairwell API error: {e}"
        return response_dictionary

    # Set Common Resources
    response_dictionary["stairwell_event_type"] = SPLUNK_OBJECT_ATTRIBUTE
    response_dictionary["stairwell_resource_type"] = SPLUNK_OBJECT_ATTRIBUTE
    response_dictionary["stairwell_resource_id"] = object_value
    # TODO: waiting for implementation in the API, before these can be completed.
    response_dictionary["stairwell_comments"] = response.get(
        "commentsMostRecent")
    # TODO: waiting for implementation in the API, before these can be completed.
    # response_dictionary["stairwell_tags"]
    response_dictionary["stairwell_opinions"] = response.get(
        "opinionsMostRecent")
    response_dictionary["stairwell_ai_assessment"] = response.get("summaryAi")

    # Set Object specific resources
    response_dictionary["stairwell_object_md5"] = response.get("fileHashMd5")
    response_dictionary["stairwell_object_sha256"] = response.get(
        "fileHashSha256")
    response_dictionary["stairwell_object_size"] = response.get(
        "fileSize", "0")
    response_dictionary["stairwell_object_first_seen_time"] = response.get(
        "sightingsFirst")
    response_dictionary["stairwell_object_mal_eval"] = response.get(
        "verdictMalevalLabels")
    response_dictionary["stairwell_object_mal_eval_probability"] = response.get(
        "verdictMalevalMaliciousProbability")
    # TODO: waiting for implementation in the API, before these can be completed.
    response_dictionary["stairwell_object_environments"] = response.get(
        "environments")
    response_dictionary["stairwell_object_yara_rule_matches"] = response.get(
        "verdictYaraRuleMatches")
    response_dictionary["stairwell_object_network_indicators_ipAddresses"] = response.get(
        "indicatorsIpsLikely")
    response_dictionary["stairwell_object_network_indicators_hostnames"] = response.get(
        "indicatorsHostnamesLikely")
    response_dictionary["stairwell_object_magic"] = response.get("fileMagic")
    response_dictionary["stairwell_object_mime_type"] = response.get(
        "fileMimeType")
    response_dictionary["stairwell_object_entropy"] = response.get(
        "fileEntropy")
    response_dictionary["stairwell_object_imp_hash"] = response.get(
        "fileHashImphash")
    response_dictionary["stairwell_object_sorted_imp_hash"] = response.get(
        "fileHashSortedImphash")
    response_dictionary["stairwell_object_tlsh"] = response.get("fileHashTlsh")
    response_dictionary["stairwell_object_signature"] = response.get(
        "signature")
    response_dictionary["stairwell_object_prevalence"] = response.get(
        "sightingsPrevalence")
    response_dictionary["stairwell_object_is_well_know"] = response.get(
        "verdictIsWellKnown")
    response_dictionary["stairwell_object_variants"] = response.get("variants")
    response_dictionary["stairwell_object_run_to_ground"] = response.get(
        "summaryRtg")
    logger.debug(f"responseDirectory: \n{response_dictionary}")
    return response_dictionary


def search_stairwell_hostname_api(search_command, logger, hostname_value):
    logger.debug("Entered search_stairwell_hostname_api")

    api_url = f"{ROOT_API_URL}{HOSTNAME_API}{hostname_value}{METADATA_PATH}"
    response_dictionary = {}

    try:
        _, response = get_from_api(search_command, logger, api_url)
    except Exception as e:
        response_dictionary["stairwell_error"] = f"Stairwell API error: {e}"
        return response_dictionary

    # Set Common Resources
    response_dictionary["stairwell_event_type"] = SPLUNK_HOSTNAME_ATTRIBUTE
    response_dictionary["stairwell_resource_type"] = SPLUNK_HOSTNAME_ATTRIBUTE
    response_dictionary["stairwell_resource_id"] = hostname_value
    # TODO: waiting for implementation in the API, before these can be completed.
    # response_dictionary["stairwell_comments"]
    # response_dictionary["stairwell_tags"]
    # response_dictionary["stairwell_opinions"]
    # response_dictionary["stairwell_ai_assessment"]

    # Set Hostname specific resources
    response_dictionary["stairwell_hostname"] = response.get("hostname")
    return response_dictionary


def get_from_api(search_command, logger, api_url):
    logger.debug("Entered get_from_api")
    headers = get_outbound_headers(search_command)

    retry_attempts = 0
    while True:
        try:
            logger.debug(f"Request: {api_url}")
            response = requests.get(api_url, headers=headers, timeout=10)
            status = response.status_code
            logger.debug(f"Response status_code {status}")
            decoded_response = response.json()
            logger.debug(f"Response: {decoded_response}")
            return status, decoded_response
        except urllib.error.HTTPError as e:
            logger.debug(f"get_from_api exception: {e}")
            if (e.code == 429 or e.code == 500) and retry_attempts <= MAX_RETRIES:
                sleep_time = int(response.headers["Retry-After"])
                if sleep_time <= 0:
                    raise
                retry_attempts += 1
                logger.info(
                    f"Status_code 429. Attempt {retry_attempts}. Sleeping for {sleep_time}")
                time.sleep(sleep_time)
            else:
                raise
