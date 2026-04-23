# Copyright (C) 2025 Stairwell Inc.

import logging
import logging.handlers
import os

str_to_log_level = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARNING,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "FATAL": logging.CRITICAL,
    "CRITICAL": logging.CRITICAL,
}

STAIRWELL_LOG_KEY = "splunk.stairwell"


def setup_logging():
    logger = logging.getLogger("splunk.stairwell")
    SPLUNK_HOME = os.environ["SPLUNK_HOME"]
    LOGGING_DEFAULT_CONFIG_FILE = os.path.join(SPLUNK_HOME, "etc", "log.cfg")

    log_level = logging.ERROR
    with open(LOGGING_DEFAULT_CONFIG_FILE, "r") as config_file:
        for line in config_file:
            tokens = line.split("=")
            if len(tokens) == 2:
                key = tokens[0].strip()
                if key == STAIRWELL_LOG_KEY:
                    log_level = str_to_log_level[tokens[1].strip()]

    logger.setLevel(log_level)
    LOGGING_FILE_NAME = "stairwell.log"
    BASE_LOG_PATH = os.path.join("var", "log", "splunk")
    LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t%(module)s:%(lineno)d - %(message)s"
    splunk_log_handler = logging.handlers.RotatingFileHandler(
        os.path.join(SPLUNK_HOME, BASE_LOG_PATH, LOGGING_FILE_NAME), mode="a"
    )
    splunk_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
    logger.addHandler(splunk_log_handler)
    return logger
