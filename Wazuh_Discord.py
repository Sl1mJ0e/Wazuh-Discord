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

try:
    import requests
    from requests.auth import HTTPBasicAuth
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global vars

debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Set paths
log_file = '{0}/logs/integrations.log'.format(pwd)

# Mapping of agent names to Discord webhook URLs
agent_webhooks = {
    'Agent-Name-1': 'YOUR DISCORD WEBHOOK HERE',
    'Agent-Name-2': 'YOUR DISCORD WEBHOOK HERE', 
    # Add more agents and their webhook URLs here
}

def main(args):
    debug("# Starting")

    # Read args
    alert_file_location = args[1]

    debug("# File location")
    debug(alert_file_location)

    # Load alert. Parse JSON object.
    with open(alert_file_location) as alert_file:
        json_alert = json.load(alert_file)
    debug("# Processing alert")
    debug(json_alert)

    # Get the rule ID
    rule_id = json_alert['rule']['id']  

    # Get agent name from alert data
    agent_name = json_alert.get('agent', {}).get('name')
    
    # Get webhook URL for this agent
    webhook = agent_webhooks.get(agent_name)

    debug("# Generating message")
    msg = generate_msg(json_alert)
    debug(msg)

    debug("# Sending message")
    send_msg(msg, webhook)


def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        f = open(log_file, "a")
        f.write(msg)
        f.close()


def generate_msg(alert):
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
    if level == 3:
        color = "3731970"  # green
    elif 6 <= level <= 12:
        color = "15870466"  # red
    else:
        color = "15919874"  # yellow

    # Create the payload with data
    payload = json.dumps({
        "embeds": [
            {
                "title": "Wazuh Alert - Rule {}".format(alert['rule']['id']),
                "color": "{}".format(color),
                "description": "{}".format(description),
                "fields": [
                    {
                        "name": "Agent",
                        "value": "{}".format(agent_name),
                        "inline": True
                    },
                    {
                        "name": "Log Source",
                        "value": "{}".format(location),
                        "inline": True
                    },
                    {
                        "name": "Rule Level",
                        "value": "{}".format(level),
                        "inline": True
                    },
                    {
                        "name": "Data",
                        "value": "SrcUser: {}, SrcIP: {}, SrcPort: {}, DstUser: {}".format(srcuser, srcip, srcport, dstuser),
                        "inline": True
                    }
                ]
            }
        ]
    })

    return payload


# noinspection PyUnreachableCode
def send_msg(msg, url):
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res = requests.post(url, data=msg, headers=headers)
    debug(res)


if __name__ == "__main__":
    try:
        # Read arguments
        bad_arguments = False
        if len(sys.argv) >= 2:
            msg = '{0} {1}'.format(
                now,
                sys.argv[1]
            )
            debug_enabled = (len(sys.argv) > 2 and sys.argv[2] == 'debug')
        else:
            msg = '{0} Wrong arguments'.format(now)
            bad_arguments = True

        # Logging the call
        f = open(log_file, 'a')
        f.write(msg + '\n')
        f.close()

        if bad_arguments:
            debug("# Exiting: Bad arguments.")
            sys.exit(1)

        # Main function
        main(sys.argv)

    except Exception as e:
        debug(str(e))
        raise
