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

"""Functions for use with the Stairwell API"""

import time
import json
from http import HTTPStatus

from urllib.error import HTTPError
import requests

SECRET_REALM = 'stairwell_realm'
SECRET_NAME = 'admin'

# The number of attempts to send API request if endpoint is busy
MAX_RETRIES = 10

ROOT_API_URL = "https://app.stairwell.com/v1/"
METADATA_PATH = "/metadata"
OBJECT_EVENT_API = "object_event/"
IP_EVENT_API = "ip_event/"
HOSTNAME_EVENT_API = "hostname_event/"
DEV_API_URL = "https://app.stairwell.dev/labs/appapi/enrichment/v1/"
SPLUNK_IP_ADDRESS_ATTRIBUTE = "ipaddress"
SPLUNK_OBJECT_ATTRIBUTE = "object"
SPLUNK_HOSTNAME_ATTRIBUTE = "hostname"

CODE_FIELD = 'code'
MESSAGE_FIELD = 'message'


def get_encrypted_token(search_command):
    """Retrieves an app configuration token, comprising password, organizationId, userId """
    secrets = search_command.service.storage_passwords
    return next(secret for secret in secrets if (secret.realm == SECRET_REALM and secret.username == SECRET_NAME)).clear_password


def get_outbound_headers(search_command):
    """Creates required headers in request to Stairwell API"""
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
    """Calls Stairwell API with an IP Address lookup"""
    logger.debug("Entered search_stairwell_ip_addresses_api")

    api_url = f"{DEV_API_URL}{IP_EVENT_API}{ip_value}"
    response_dictionary = {}

    try:
        response = get_from_api(search_command, logger, api_url)
    except StairwellAPIStatusException as e:
        response_dictionary["stairwell_status"] = e
        return response_dictionary
    except StairwellAPIErrorException as e:
        response_dictionary["stairwell_error"] = e
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
    response_dictionary["stairwell_ip_address"] = ip_value
    response_dictionary["stairwell_uninteresting_addr"] = response.get(
        "uninterestingAddr")
    response_dictionary["stairwell_opinions_most_recent"] = response.get(
        "opinionsMostRecent", [])
    response_dictionary["stairwell_comments_most_recent"] = response.get(
        "commentsMostRecent", [])
    response_dictionary["stairwell_associated_hostnames"] = response.get(
        "associatedHostnames", [])
    return response_dictionary


def search_stairwell_object_api(search_command, logger, object_value):
    """Calls Stairwell API with an Object lookup"""
    logger.debug("Entered search_stairwell_object_api")

    api_url = f"{DEV_API_URL}{OBJECT_EVENT_API}{object_value}"
    response_dictionary = {}

    try:
        response = get_from_api(search_command, logger, api_url)
    except StairwellAPIStatusException as e:
        response_dictionary["stairwell_status"] = e
        return response_dictionary
    except StairwellAPIErrorException as e:
        response_dictionary["stairwell_error"] = e
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
    response_dictionary["stairwell_object_sha1"] = response.get(
        "fileHashSha1")
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
    response_dictionary["stairwell_object_environments"] = response.get(
        "environments")
    response_dictionary["stairwell_object_yara_rule_matches"] = response.get(
        "verdictYaraRuleMatches")
    response_dictionary["stairwell_object_network_indicators_ipAddresses"] = response.get(
        "indicatorsIpsLikely")
    response_dictionary["stairwell_object_network_indicators_hostnames"] = response.get(
        "indicatorsHostnamesLikely")
    response_dictionary["stairwell_object_network_indicators_hostnames_private"] = response.get(
        "indicatorsHostnamesPrivate")
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
    """Calls Stairwell API with a hostname lookup"""
    logger.debug("Entered search_stairwell_hostname_api")

    api_url = f"{DEV_API_URL}{HOSTNAME_EVENT_API}{hostname_value}"
    response_dictionary = {}

    try:
        response = get_from_api(search_command, logger, api_url)
    except StairwellAPIStatusException as e:
        response_dictionary["stairwell_status"] = e
        return response_dictionary
    except StairwellAPIErrorException as e:
        response_dictionary["stairwell_error"] = e
        return response_dictionary

    # Set Common Resources
    response_dictionary["stairwell_event_type"] = SPLUNK_HOSTNAME_ATTRIBUTE
    response_dictionary["stairwell_resource_type"] = SPLUNK_HOSTNAME_ATTRIBUTE
    response_dictionary["stairwell_resource_id"] = hostname_value
    # TODO: waiting for implementation in the API, before these can be completed.
    response_dictionary["stairwell_comments"] = response.get(
        "commentsMostRecent")
    # response_dictionary["stairwell_tags"]
    response_dictionary["stairwell_opinions"] = response.get(
        "opinionsMostRecent")
    # response_dictionary["stairwell_ai_assessment"]

    # Set Hostname specific resources
    response_dictionary["stairwell_hostname"] = hostname_value
    response_dictionary["stairwell_hostname_a_records"] = response.get(
        "lookupARecords")
    response_dictionary["stairwell_hostname_aaaa_records"] = response.get(
        "lookupAaaaRecords")
    response_dictionary["stairwell_hostname_mx_records"] = response.get(
        "lookupMxRecords")
    return response_dictionary


def get_from_api(search_command, logger, api_url):
    """Calls an API with provided api_url and handles error responses."""
    logger.debug("Entered get_from_api")
    headers = get_outbound_headers(search_command)

    retry_attempts = 0
    while True:
        try:
            logger.debug(f"Request: {api_url}")
            response = requests.get(api_url, headers=headers, timeout=10)
            status = response.status_code
            logger.debug(f"Response status_code {status}")
            # successful response
            if status == HTTPStatus.OK:
                decoded_response = response.json()
                logger.debug(f"Response: {decoded_response}")
                return decoded_response

            # handle non successful response
            retry_attempts = process_error(
                response, status, retry_attempts, logger)

        except HTTPError as e:
            logger.debug(f"get_from_api exception: {e}")
            retry_attempts = process_error(
                response, e.code, retry_attempts, logger)
        except ValueError as e:
            error_message = "Unable to decode response"
            logger.error(error_message)
            raise StairwellAPIErrorException(error_message, None) from e
        except requests.ReadTimeout as e:
            error_message = "API request timeout"
            logger.error(error_message)
            raise StairwellAPIErrorException(error_message, None) from e


def process_error(response, code, retry_attempts, logger):
    """Provide error handling and retry functionality based on API response"""
    logger.debug(f"process_error code:{code} \nresponse:{response} ")
    if code in (HTTPStatus.TOO_MANY_REQUESTS, HTTPStatus.INTERNAL_SERVER_ERROR):
        # Retry-After response
        sleep_time = int(response.headers["Retry-After"])
        if retry_attempts <= MAX_RETRIES and sleep_time > 0:
            retry_attempts += 1
            logger.info(
                f"HTTP: TOO_MANY_REQUESTS. Attempt {retry_attempts}. Sleeping for {sleep_time}")
            time.sleep(sleep_time)
            return retry_attempts
        else:
            if retry_attempts > MAX_RETRIES:
                logger.error(
                    f"HTTP Code {code}. Stairwell API {MAX_RETRIES} retried attempted")
                raise StairwellAPIErrorException(
                    f"Stairwell API {MAX_RETRIES} retried attempted", code)

            error_message = f"HTTP: {code}"
            logger.error(error_message)
            raise StairwellAPIErrorException(error_message, code)
    elif code == HTTPStatus.NOT_FOUND:
        logger.debug("Handle HTTP: NOT_FOUND")
        decoded_response = response.json()
        error_message = f"HTTP: {code}, Reason: {decoded_response}"
        logger.error(error_message)
        raise StairwellAPIStatusException(error_message, code)
    else:
        #  Other non successful responses
        if CODE_FIELD in response and MESSAGE_FIELD in response:
            code = response.get(CODE_FIELD)
            message = response.get(MESSAGE_FIELD)
            error_message = f"Status: {code}, Reason: {message}"
            logger.error(error_message)
            raise StairwellAPIStatusException(error_message, code)
        raise StairwellAPIErrorException(
            f"HTTP: {code}", code)


class StairwellAPIStatusException(Exception):
    """Exception used when a Stairwell API request returns an error code"""

    def __init__(self, message, errors):
        super().__init__(message)

        self.errors = errors


class StairwellAPIErrorException(Exception):
    """Exception used when a Stairwell API request fails"""

    def __init__(self, message, errors):
        super().__init__(message)

        self.errors = errors
