# Copyright (C) 2025 Stairwell Inc.

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "splunklib"))
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "stairwelllib"))
from stairwelllib.logging import setup_logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "stairwelllib"))
from stairwelllib.stairwellapi import searchStairwellIpAddressesAPI, searchStairwellObjectAPI, searchStairwellHostnameAPI

@Configuration()
class Stairwell(StreamingCommand):
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
            logger.debug(f"record before = {record}")
            if 'ip_field' in locals() and ip_field in record and record[ip_field] != "":
                # Send request to Stairwell API
                responseDictionary = searchStairwellIpAddressesAPI(self, logger, record[ip_field])
                for key, value in responseDictionary.items():
                    record[key] = value

            elif 'object_field' in locals() and object_field in record and record[object_field] != "":
                # Send request to Stairwell API
                responseDictionary = searchStairwellObjectAPI(self, logger, record[object_field])
                for key, value in responseDictionary.items():
                    record[key] = value

            elif 'hostname_field' in locals() and hostname_field in record and record[hostname_field] != "":
                hostname_value = record[hostname_field]
                # Send request to Stairwell API
                responseDictionary = searchStairwellHostnameAPI(self, logger, record[hostname_field])
                for key, value in responseDictionary.items():
                    record[key] = value               

            logger.debug(f"record after = {record}")

            try:
                yield record
            except StopIteration:
                return

        logger.info("Stairwell - stream - exit")

dispatch(Stairwell, sys.argv, sys.stdin, sys.stdout, __name__)
