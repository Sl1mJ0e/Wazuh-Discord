#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# March 13, 2018.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import json
import sys
import time
import os
from typing import Dict
from enum import Enum

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Constants
LOG_FILE = '{0}/logs/integrations.log'
ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')

# Custom exceptions
class InvalidArgumentsError(Exception):
    pass

class WazuhIntegrationError(Exception):
    pass

def main(args: Dict[str, str]) -> None:
    try:
        alert_file_location = args['alert_file_location']
        debug_enabled = args.get('debug_enabled', False)

        debug("# Starting")
        debug(f"# File location: {alert_file_location}")

        with open(alert_file_location) as alert_file:
            json_alert = json.load(alert_file)
        debug("# Processing alert")
        debug(json_alert)

        agent_name = json_alert.get('agent', {}).get('name')
        webhook = get_agent_webhook(agent_name)

        debug("# Generating message")
        msg = generate_msg(json_alert)
        debug(msg)

        debug("# Sending message")
        send_msg(msg, webhook)

    except InvalidArgumentsError as e:
        debug(str(e))
        sys.exit(1)
    except WazuhIntegrationError as e:
        debug(str(e))
        raise

def debug(msg: str) -> None:
    if ENVIRONMENT != 'production':
        now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
        msg = f"{now}: {msg}\n"
        print(msg)
        with open(get_log_file(), "a") as log_file:
            log_file.write(msg)

def get_agent_webhook(agent_name: str) -> str:
    webhooks_file = os.path.join(os.path.dirname(__file__), 'agent_webhooks', 'webhooks.json')
    with open(webhooks_file, 'r') as file:
        agent_webhooks = json.load(file)
    webhook = agent_webhooks.get(agent_name)
    if webhook is None:
        raise WazuhIntegrationError(f"No webhook found for agent: {agent_name}")
    return webhook

def generate_msg(alert: Dict) -> str:
    # Extract the 'data' key if it exists, otherwise set defaults
    data = alert.get('data', {})
    srcport = data.get('srcport', 'N/A')
    srcuser = data.get('srcuser', 'N/A')
    dstuser = data.get('dstuser', 'N/A')
    srcip = data.get('srcip', 'N/A')

    # If srcport is not found under 'data', try to look for it under 'parameters' and 'parameters.alert.data'
    if srcport == 'N/A':
        parameters_data_srcport = data.get('parameters', {}).get('alert', {}).get('data', {}).get('srcport', 'N/A')
        srcport = parameters_data_srcport

    # If srcuser is not found under 'data', try to look for it under 'parameters' and 'parameters.alert.data'
    if srcuser == 'N/A':
        parameters_data_srcuser = data.get('parameters', {}).get('alert', {}).get('data', {}).get('srcuser', 'N/A')
        srcuser = parameters_data_srcuser

    # If dstuser is not found under 'data', try to look for it directly under 'data'
    if dstuser == 'N/A':
        dstuser = data.get('dstuser', 'N/A')

    # Extract other necessary fields
    level = alert['rule']['level']
    description = alert['rule']['description']
    agent_name = alert['agent']['name']
    location = alert['location']

    # Determine color based on the rule level
    color = get_color_for_level(level)

    # Create the payload with data
    payload = json.dumps({
        "embeds": [
            {
                "title": f"Wazuh Alert - Rule {alert['rule']['id']}",
                "color": color,
                "description": description,
                "fields": [
                    {
                        "name": "Agent",
                        "value": agent_name,
                        "inline": True
                    },
                    {
                        "name": "Log Source",
                        "value": location,
                        "inline": True
                    },
                    {
                        "name": "Rule Level",
                        "value": str(level),
                        "inline": True
                    },
                    {
                        "name": "Data",
                        "value": f"SrcUser: {srcuser}, SrcIP: {srcip}, SrcPort: {srcport}, DstUser: {dstuser}",
                        "inline": True
                    }
                ]
            }
        ]
    })

    return payload

def get_color_for_level(level: int) -> str:
    if level == 3:
        return "3731970"  # green
    elif 6 <= level <= 12:
        return "15870466"  # red
    else:
        return "15919874"  # yellow

def send_msg(msg: str, url: str) -> None:
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    try:
        requests.post(url, data=msg, headers=headers)
    except requests.exceptions.RequestException as e:
        raise WazuhIntegrationError(f"Error sending message to Discord: {str(e)}")

def get_log_file() -> str:
    pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    return os.path.join(pwd, 'logs', 'integrations.log')

if __name__ == "__main__":
    try:
        if len(sys.argv) < 2:
            raise InvalidArgumentsError("Wrong arguments")

        alert_file_location = sys.argv[1]
        debug_enabled = len(sys.argv) > 2 and sys.argv[2] == 'debug'

        main({
            'alert_file_location': alert_file_location,
            'debug_enabled': debug_enabled
        })

    except Exception as e:
        debug(str(e))
        raise
