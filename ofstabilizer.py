#!/usr/bin/env python3

import json
import requests
import sys
import time

URL_PREFIX = "http://{}:8181/restconf/{}"
INVENTORY_URL = URL_PREFIX + "/opendaylight-inventory:nodes"
TABLE_URL = INVENTORY_URL + "/node/{}/flow-node-inventory:table/{}"
FLOW_URL = TABLE_URL + "/flow/{}"
OP = "operational"
CFG = "config"
TABLE_ID = 0
LLDP = 0x88cc
ARP = 0x0806
HEADERS = {"content-type": "application/json", "accept": "application/json"}
AUTH = ("admin", "admin")

TIME_INTERVAL = 2 # check the flow rules every _ seconds

FLOW_RULE_TEMPLATE='''
{
    \"flow\": {
        \"id\": %s,
        \"match\": {
            \"ethernet-match\": {
                \"ethernet-type\": {
                    \"type\": %d
                }
            }
        },
        \"priority\": %d,
        \"idle-timeout\": 0,
        \"hard-timeout\": 0,
        \"table_id\": 0,
        \"instructions\": {
            \"instruction\": [
                {
                    \"order\": 0,
                    \"apply-actions\": {
                        \"action\": [
                            {
                                \"order\": 0,
                                \"output-action\": {
                                    \"output-node-connector\": \"CONTROLLER\",
                                    \"max-length\": 65535
                                }
                            }
                        ]
                    }
                }
            ]
        }
    }
}
'''

def is_matching_ethernet_protocol(flow, protocol):
    try:
        match = flow['match']
        if len(match) > 1:
            return False
        ethernet_match = match['ethernet-match']
        if len(ethernet_match) > 1:
            return False
        return ethernet_match['ethernet-type']['type'] == protocol
    except Exception:
        return False

def is_sending_to_controller(flow):
    try:
        instructions = flow['instructions']['instruction']
        if len(instructions) > 1:
            return False
        actions = instructions[0]['apply-actions']['action']
        if len(actions) > 1:
            return False
        return actions[0]['output-action']['output-node-connector'].upper() == 'CONTROLLER'
    except Exception:
        return False

def to_hex(value):
    return '0x{:04x}'.format(value)

def check_and_install(controller_ip, node_id, proto):
    tbl_url = TABLE_URL.format(controller_ip, OP, node_id, TABLE_ID)

    response = requests.get(tbl_url, headers=HEADERS, auth=AUTH)
    checked = False
    try:
        table = response.json()['flow-node-inventory:table'][0]
        for flow in table['flow']:
            if not is_matching_ethernet_protocol(flow, proto):
                continue
            if not is_sending_to_controller(flow):
                continue
            checked = True
            break;
    except Exception:
        pass

    print('{} status: {}'.format(node_id, checked))

    if not checked:
        fl_url = FLOW_URL.format(controller_ip, CFG, node_id, TABLE_ID, to_hex(proto))
        priority = 100 if proto == LLDP else 1
        data = FLOW_RULE_TEMPLATE % ('\"{}\"'.format(to_hex(proto)), proto, priority)
        response = requests.put(fl_url, headers=HEADERS, data=data, auth=AUTH)
        print(response.status_code)

def stabilize(controller_ip):
    try:
        while True:
            pattern = INVENTORY_URL
            url = pattern.format(controller_ip, OP)

            response = requests.get(url, headers=HEADERS, auth=AUTH)
            if response.ok:
                inventory = response.json()
                for node in inventory['nodes']['node']:
                    node_id = node['id']
                    print(node_id)
                    check_and_install(controller_ip, node_id, LLDP)
                    check_and_install(controller_ip, node_id, ARP)
            time.sleep(TIME_INTERVAL)
    except KeyboardInterrupt as e:
        return
    except Exception as e:
        raise e

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python {} CONTROLLER_IP".format(__file__))
        sys.exit()
    stabilize(sys.argv[1])
