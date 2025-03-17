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

"""Streaming search command for Stairwell"""

import sys
from stairwelllib.stairwellapi import search_stairwell_ip_addresses_api
from stairwelllib.stairwellapi import search_stairwell_object_api
from stairwelllib.stairwellapi import search_stairwell_hostname_api
from stairwelllib.logging import setup_logging
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option

@Configuration()
class Stairwell(StreamingCommand):
    """Class providing a streaming search command for Stairwell"""

    ip = Option(require=False)
    object = Option(require=False)
    hostname = Option(require=False)

    def stream(self, records):
        logger = setup_logging()
        logger.info("Stairwell - stream - entered")

        arg_counter = 0
        if self.ip and len(self.ip) != 0:
            arg_counter += 1
            ip_field = self.ip
        if self.object and len(self.object) != 0:
            arg_counter += 1
            object_field = self.object
        if self.hostname and len(self.hostname) != 0:
            arg_counter += 1
            hostname_field = self.hostname
        if arg_counter == 0:
            logger.error("No input field specified")
            raise ValueError("No input field specified")
        elif arg_counter > 1:
            logger.error("Multiple inputs received")
            raise ValueError("Multiple inputs received")

        for record in records:
            logger.debug("record before = %s", record)
            if 'ip_field' in locals() and ip_field in record and record[ip_field] != "":
                # Send request to Stairwell API
                response_dictionary = search_stairwell_ip_addresses_api(
                    self, logger, record[ip_field])
                for key, value in response_dictionary.items():
                    record[key] = value

            elif 'object_field' in locals() and object_field in record and record[object_field] != "":
                # Send request to Stairwell API
                response_dictionary = search_stairwell_object_api(
                    self, logger, record[object_field])
                for key, value in response_dictionary.items():
                    record[key] = value

            elif 'hostname_field' in locals() and hostname_field in record and record[hostname_field] != "":
                # Send request to Stairwell API
                response_dictionary = search_stairwell_hostname_api(
                    self, logger, record[hostname_field])
                for key, value in response_dictionary.items():
                    record[key] = value

            logger.debug("record after = %s", record)

            try:
                yield record
            except StopIteration:
                logger.error("Stairwell - stream - received StopIteration")
                return

        logger.info("Stairwell - stream - exit")


dispatch(Stairwell, sys.argv, sys.stdin, sys.stdout, __name__)
