# Copyright (C) 2025 Stairwell Inc.

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

root_api_url = "https://app.stairwell.com/v1/"
metadata_path = "/metadata"
objects_api = "objects/"
ip_api = "ipAddresses/"
hostname_api = "hostnames/"

dev_api_url = "https://app.stairwell.dev/labs/appapi/enrichment/v1/object_event/"


def get_encrypted_token(search_command):
    secrets = search_command.service.storage_passwords
    return next(secret for secret in secrets if (secret.realm == SECRET_REALM and secret.username == SECRET_NAME)).clear_password

def getOutboundHeaders(search_command):
    secrets = get_encrypted_token(search_command)
    secretsJson = json.loads(secrets)
    authToken = secretsJson["password"]
    organizationId = secretsJson["organizationId"]
    userId = secretsJson["userId"]
    headers = {
        "Authorization": f"{authToken}",
        "Organization-Id": f"{organizationId}",
        "User-Id": f"{userId}",
        "accept": "application/json"
    }
    return headers
     
def searchStairwellIpAddressesAPI(search_command, logger, ipValue):
    logger.debug("Entered searchStairwellIpAddressesAPI")

    api_url = f"{root_api_url}{ip_api}{ipValue}{metadata_path}"
    responseDictionary = {}

    try:
        response = getFromAPI(search_command, logger, api_url)
    except Exception as e:
        responseDictionary["stairwell_error"] = f"Could not connect to Stairwell API: {e}"
        return responseDictionary
    
    # Set Common Resources
    responseDictionary["stairwell_event_type"] = "ipaddress"
    responseDictionary["stairwell_resource_type"] = "ipaddress"
    responseDictionary["stairwell_resource_id"] = ipValue
    # responseDictionary["stairwell_comments"]
    # responseDictionary["stairwell_tags"]
    # responseDictionary["stairwell_opinions"]
    # responseDictionary["stairwell_ai_assessment"]

    # Set IP Address specific resources
    responseDictionary["stairwell_ip_address"] = response.get("ipAddress")
    responseDictionary["stairwell_event_type"] = "ipAddress"
    responseDictionary["stairwell_tags"] = response.get("tags", [])
    return responseDictionary
    
def searchStairwellObjectAPI(search_command, logger, objectValue):
    logger.debug("Entered searchStairwellObjectAPI")

    api_url = f"{dev_api_url}{objectValue}"
    responseDictionary = {}

    try:
        response = getFromAPI(search_command, logger, api_url)
    except Exception as e:
        responseDictionary["stairwell_error"] = f"Could not connect to Stairwell API: {e}"
        return responseDictionary

    # Set Common Resources
    responseDictionary["stairwell_event_type"] = "object"
    responseDictionary["stairwell_resource_type"] = "object"
    responseDictionary["stairwell_resource_id"] = objectValue
    # responseDictionary["stairwell_comments"]
    # responseDictionary["stairwell_tags"]
    # responseDictionary["stairwell_opinions"]
    responseDictionary["stairwell_ai_assessment"] = response.get("summaryAi")

    # Set Object specific resources
    responseDictionary["stairwell_object_md5"] = response.get("fileHashMd5")
    responseDictionary["stairwell_object_sha256"] = response.get("fileHashSha256")
    responseDictionary["stairwell_object_size"] = response.get("fileSize", "0")
    responseDictionary["stairwell_object_first_seen_time"] = response.get("sightingsFirst")
    responseDictionary["stairwell_object_mal_eval"] = response.get("verdictMalevalLabels")
    responseDictionary["stairwell_object_mal_eval_probability"] = response.get("verdictMalevalMaliciousProbability")
    # responseDictionary["stairwell_object_environments"]
    responseDictionary["stairwell_object_yara_rule_matches"] = response.get("verdictYaraRuleMatches")
    responseDictionary["stairwell_object_network_indicators_ipAddresses"] = response.get("indicatorsIpsLikely")
    responseDictionary["stairwell_object_network_indicators_hostnames"] = response.get("indicatorsHostnamesLikely")
    responseDictionary["stairwell_object_magic"] = response.get("fileMagic")
    responseDictionary["stairwell_object_mime_type"] = response.get("fileMimeType")
    responseDictionary["stairwell_object_entropy"] = response.get("fileEntropy")
    responseDictionary["stairwell_object_imp_hash"] = response.get("fileHashImphash")
    responseDictionary["stairwell_object_sorted_imp_hash"] = response.get("fileHashSortedImphash")
    responseDictionary["stairwell_object_tlsh"] = response.get("fileHashTlsh")
    responseDictionary["stairwell_object_signature"] = response.get("signature")
    responseDictionary["stairwell_object_prevalence"] = response.get("sightingsPrevalence")
    responseDictionary["stairwell_object_is_well_know"] = response.get("verdictIsWellKnown")
    responseDictionary["stairwell_object_variants"] = response.get("variants")
    responseDictionary["stairwell_object_run_to_ground"] = response.get("summaryRtg")
    logger.debug(f"responseDirectory: \n{responseDictionary}")
    return responseDictionary
     
def searchStairwellHostnameAPI(search_command, logger, hostnameValue):
    logger.debug("Entered searchStairwellHostnameAPI")

    api_url = f"{root_api_url}{hostname_api}{hostnameValue}{metadata_path}"
    responseDictionary = {}

    try:
        response = getFromAPI(search_command, logger, api_url)
    except Exception as e:
        responseDictionary["stairwell_error"] = f"Could not connect to Stairwell API: {e}"
        return responseDictionary
    
    # Set Common Resources
    responseDictionary["stairwell_event_type"] = "hostname"
    responseDictionary["stairwell_resource_type"] = "hostname"
    responseDictionary["stairwell_resource_id"] = hostnameValue
    # responseDictionary["stairwell_comments"]
    # responseDictionary["stairwell_tags"]
    # responseDictionary["stairwell_opinions"]
    # responseDictionary["stairwell_ai_assessment"]

    # Set Hostname specific resources
    responseDictionary["stairwell_hostname"] = response.get("hostname")
    return responseDictionary

def getFromAPI(search_command, logger, api_url):   
    logger.debug("Entered getFromAPI")
    headers = getOutboundHeaders(search_command)

    retryAttempts = 0
    while True:
        try:
            response = requests.get(api_url, headers=headers)
            decodedResponse = response.json()
            logger.debug(f"Request: {api_url}")
            logger.debug(f"Response: {decodedResponse}")
            if 'code' in decodedResponse and 'message' in decodedResponse:
                code = decodedResponse.get("code")
                message = decodedResponse.get("message")
                raise Exception(f"Could not connect to Stairwell API. Error: {code}, Reason: {message}")
            return decodedResponse
        except urllib.error.HTTPError as e:
            logger.debug(f"getFromAPI exception: {e}")
            if (e.code == 429 or e.code == 500) and retryAttempts <= MAX_RETRIES:
                sleep_time = int(response.headers["Retry-After"])
                if sleep_time <= 0:
                    raise
                retryAttempts += 1
                logger.info(f"Status_code 429. Attempt {retryAttempts}. Sleeping for {sleep_time}")
                time.sleep(sleep_time)
            else:
                raise
