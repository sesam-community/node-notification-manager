#!/usr/bin/env python
import json
import logging
import os
import re
import sys
from time import sleep

import sesamclient
import fnmatch
from portal import PortalConnection


# define required and optional environment variables
required_env_vars = ["node_endpoint", "jwt"]
optional_env_vars = ["loglevel", "rules", "interval"]


# Define logger
format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logger = logging.getLogger('NotificationManager')
stdout_handler = logging.StreamHandler()
stdout_handler.setFormatter(logging.Formatter(format_string))
logger.addHandler(stdout_handler)

logger.setLevel({"INFO": logging.INFO,
                 "DEBUG": logging.DEBUG,
                 "WARN": logging.WARNING,
                 "ERROR": logging.ERROR}.get(os.getenv("loglevel", "INFO")))  # Default loglevel: INFO


class AppConfig(object):
    pass


config = AppConfig()


# load variables
missing_env_vars = list()
for env_var in required_env_vars:
    value = os.getenv(env_var)
    if not value:
        missing_env_vars.append(env_var)
    setattr(config, env_var, value)

if len(missing_env_vars) != 0:
    logger.error(f"Missing the following required environment variable(s) {missing_env_vars}")
    sys.exit(1)

# try:
#     #rules = json.loads(config.rules)
# except ValueError:
#     logger.error("The 'rules' environment variable doesn't cotain valid Json.")
#     sys.exit(1)

with open('example_config.json', 'r') as f:
    raw_example = f.read()
    rules = json.loads(raw_example)

# Todo: Validate all rules. Should contain: 'template', 'pipes'


def is_pattern_match(pattern, input_string):
    regular_expression = fnmatch.translate(pattern)
    compiled_pattern = re.compile(regular_expression)
    match = compiled_pattern.match(input_string)
    return match is not None


def get_matching_rules(pipe_id):
    pattern_matched_rules = list()
    for rule_definition in rules:
        rule_patterns = rule_definition.get("pipes")
        if rule_patterns:
            for pattern in rule_patterns:
                if is_pattern_match(pattern, pipe_id):
                    pattern_matched_rules.append(rule_definition.get("template").copy())
    return pattern_matched_rules


# Create connections
node_conn = sesamclient.Connection(
                sesamapi_base_url=config.node_endpoint,
                jwt_auth_token=config.jwt)
portal_conn = PortalConnection(config.jwt)

subscription_id = node_conn.get_license().get("_id")
logger.debug(f"Node subscription_id: '{subscription_id}'")


while True:

    # get list of all pipes from node
    logger.info("Starting check for updated notification rules.")
    pipes = node_conn.get_pipes()

    for pipe in pipes:
        # get rules from portal endpoint
        logger.debug("Checking for rules matching pipe '{}'".format(pipe.id))
        matched_rules = list()
        matched_rules = get_matching_rules(pipe.id)
        if matched_rules:
            logger.debug("Found {} rules matching pipe '{}'.".format(len(matched_rules), pipe.id))
            existing_rules = portal_conn.get_pipe_notification_rules(subscription_id, pipe.id)
            update_count = 0
            matched_existence_rules = list()
            for rule in matched_rules:
                if rule:
                    try:
                        rule["recipients"][0]["id"] = (rule["recipients"][0]["id"]).replace("<SUBSCRIPTION_ID>", subscription_id)
                    except KeyError:
                        logger.error("Misconfigured rule. Make sure to follow the required layout from the example.")
                        continue

                    same_name_existing_rule = None

                    for existing_rule in existing_rules:
                        if existing_rule.get("name") == rule.get("name"):
                            same_name_existing_rule = existing_rule
                            rule["id"] = existing_rule.get("id")
                            matched_existence_rules.append(rule)

                    if not rule == same_name_existing_rule:
                        if same_name_existing_rule:
                            logger.info("Updating existing rule '{}' for pipe '{}'".format(rule.get("name"), pipe.id))
                            portal_conn.update_pipe_notification_rule(subscription_id, pipe.id, rule.get("id"), rule)
                        else:
                            logger.info("Creating new rule '{}' for pipe '{}'".format(rule.get("name"), pipe.id))
                            portal_conn.add_pipe_notification_rule(subscription_id, pipe.id, rule)
                        update_count += 1

            if update_count == 0:
                logger.debug("No new/changed rules found for pipe '{}'".format(pipe.id))

            # check for rules created directly on the node that's not present in the microservice config
            manually_created_rules = list()
            for existing in existing_rules:
                if existing not in matched_existence_rules:
                    manually_created_rules.append(existing)

            if len(manually_created_rules) > 0:
                for manually in manually_created_rules:
                    logger.warning("Unregistered notification rule '{}' found on node for pipe '{}'"
                                   .format(manually["name"], pipe.id))

    logger.info("Finished notification check")

    sleep_interval = config.interval if hasattr(config, "interval") else 3600
    logger.info(f"Going to sleep. Will check again in {sleep_interval} seconds")
    sleep(sleep_interval)



