#!/usr/bin/env python3

import json
import requests
import sys
import time

URL_PREFIX = "http://{}:8181/restconf/{}"
INVENTORY = "/opendaylight-inventory:nodes"
FLOW = INVENTORY + "/node/{}/flow-node-inventory:table/{}/flow/{}"
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

def to_hex(value):
    return '0x{:04x}'.format(value)

def check_and_install(controller_ip, node_id, proto):
    pattern = URL_PREFIX + FLOW

    op_url = pattern.format(controller_ip, OP, node_id, TABLE_ID, to_hex(proto))
    cfg_url = pattern.format(controller_ip, CFG, node_id, TABLE_ID, to_hex(proto))

    print(op_url)
    print(cfg_url)

    response = requests.get(op_url, headers=HEADERS, auth=AUTH)
    if not response.ok:
        priority = 100 if proto == LLDP else 1
        data = FLOW_RULE_TEMPLATE % ('\"{}\"'.format(to_hex(proto)), proto, priority)
        response = requests.put(cfg_url, headers=HEADERS, data=data, auth=AUTH)
        print(response.status_code)

def stabilize(controller_ip):
    try:
        while True:
            pattern = URL_PREFIX + INVENTORY
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
