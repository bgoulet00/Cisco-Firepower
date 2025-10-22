'''
in the FMC you can perform a hit count analysis for a policy against a singe FTD appliance.  to see if a rule is taking hits on any device
you need to manually run the hit count for each FTD.  this script will perform hitcount analysis for a policy against all devices in inventory
and then offer multiple options on how to report in the output.

Detailed Report: One line item for every device that hits on a rule.  this can become big quickly for large policies and device inventories
Most Recent Hit Only: One line item per rule, listing only the device/timestamp with the most recent hit
Zero Hits Only: List only rules that have no hits across all devices
'''

from typing import Optional, List, Dict, Any
import requests
from requests.auth import HTTPBasicAuth
import json
import csv
import time
import os
from datetime import datetime
from common.fmc_lib import fmc_login, get_fmc_policies, get_fmc_rules
from fmc_config import BASE_URL

# Disable SSL warnings
import urllib3
urllib3.disable_warnings()

TIMEOUT = 30

def get_devicerecords(base_url: str, token: str, DUUID: str) -> Optional[List[Dict[str, Any]]]:
    """Get a list of all device records in inventory.
    no pagination employed here, if you have more than 1000 devices you will need to implement pagination

    Args:
        base_url (str): The base URL of the FMC API.
        token (str): The authentication token for the FMC API.
        DUUID (str): The domain UUID.
    Returns:
        list: A list of device record dicts or None.
    """    
    
    #query paramaters to control results limit and offset. 1000 is max limit
    limit = 1000
    offset = 0
    querystring = {'offset':offset,'limit':limit}
    header = {'X-auth-access-token': token,
              'Accept': 'application/json'}
    try:
        response = requests.get(
        base_url + '/api/fmc_config/v1/domain/' + DUUID + '/devices/devicerecords?expanded=true',
        headers=header,
        params=querystring,
        verify=False,
        )
    except Exception as e:
        print("Error occurred while retrieving device records:", e)
        return None
    if not response.ok:
        print("Failed to retrieve device records:", response.text)
        return None
    data = response.json()
    return data.get('items')


def get_policy_hits(base_url: str, token: str, DUUID: str, policy_id: str, device_id: str) -> Optional[List[Dict[str, Any]]]:
    """Get the hit count information for a specific policy and device.
    no pagination employed here, if you have more than 1000 rules you will need to implement pagination

    Args:
        base_url (str): The base URL of the FMC API.
        token (str): The authentication token for the FMC API.
        DUUID (str): The domain UUID.
        policy_id (str): The access control policy ID.
        device_id (str): The device ID.
    Returns:
        list: A list of hit count dictionaries for the specified policy and device or None.
    """
    #query paramaters to control results
    limit = 1000
    offset = 0
    #cisco documentation shows filter should be in format "deviceID:{id}" but it does not work with the {} braces
    querystring = {'offset':offset,
                   'limit':limit,
                #    'filter':'"deviceId:' + device_id + '"',
                   'filter': f'deviceId:{device_id}',
                   'expanded':'true'}
    header = {'X-auth-access-token': token,
              'Accept': 'application/json'}
    try:
        response = requests.get(
            base_url + '/api/fmc_config/v1/domain/' + DUUID + '/policy/accesspolicies/' + policy_id + '/operational/hitcounts',
        headers=header,
        params=querystring,
        verify=False,
        )
    except Exception as e:
        print("Error occurred while retrieving policy hits:", e)
        return None
    if not response.ok:
        print("Failed to retrieve policy hits:", response.text)
        return None
    data = response.json()
    return data.get('items')

def update_policy_hits(base_url: str, token: str, DUUID: str, policy_id: str, device_id: str) -> bool:
    """Update the hit count information for a specific policy and device.

    Args:
        base_url (str): The base URL of the FMC API.
        token (str): The authentication token for the FMC API.
        DUUID (str): The domain UUID.
        policy_id (str): The access control policy ID.
        device_id (str): The device ID.
    Returns:
        bool: True if the update was successful, False otherwise.
    """    

    #cisco documentation shows filter should be in format "deviceID:{id}" but it does not work with the {} braces
    # querystring = {'filter':'"deviceId:' + device_id + '"',
    #                }
    querystring = {'filter': f'deviceId:{device_id}',
                   }
    header = {'X-auth-access-token': token,
              'Content-Type': 'application/json',
              'Accept': 'application/json'}
    
    try:
        response = requests.put(
            base_url + '/api/fmc_config/v1/domain/' + DUUID + '/policy/accesspolicies/' + policy_id + '/operational/hitcounts',
        headers=header,
        params=querystring,
        verify=False,
        )
        # print(f"sent request {response.url}")
    except requests.exceptions.RequestException as e:
        print("Error occurred while updating policy hits:", e)
        return False
    if not response.ok:
        print("Failed to update policy hits:", response.text)
        return False
    try:
        data = response.json() or {}
    except ValueError:
        print("Failed to parse JSON from update policy hits response")
        return False

    err = data.get('error')
    if err:
        print(f"Error occurred while updating policy hits: {err}")
        return False

    task_id = (data.get('metadata') or {}).get('task', {}).get('id')
    if not task_id:
        print("No task id returned from update policy hits.")
        return False
    return get_task_status(base_url, token, DUUID, task_id)

def get_task_status(base_url: str, token: str, DUUID: str, task_id: str) -> bool:
    """Get the status of a specific task, trying up to max attempts

    Args:
        base_url (str): The base URL of the FMC API.
        token (str): The authentication token for the FMC API.
        DUUID (str): The domain UUID.
        task_id (str): The task ID.
    Returns:
        bool: True if the task completed successfully, False otherwise.
    """   

    wait_time = 5
    attempt_count = 0
    max_attempts = 5
    header = {'X-auth-access-token': token,
              'Accept': 'application/json'}
    # pause to give task a chance to run
    time.sleep(wait_time)
    while True:
        attempt_count += 1
        if attempt_count > max_attempts:
            print("Task did not complete within the expected time")
            return False
        if attempt_count > 1:
            print(f"Checking task status attempt {attempt_count}")
        try:
            response = requests.get(
                base_url + '/api/fmc_config/v1/domain/' + DUUID + '/job/taskstatuses/' + task_id,
            headers=header,
            verify=False,
            timeout=TIMEOUT,
            )
        except requests.exceptions.RequestException as e:
            print("Transport error while fetching task status:", e)
            return False
        try:
            data = response.json()
        except ValueError as e:
            print("Failed to parse JSON response", e)
            data = {}
        if not response.ok:
            print(f"Failed to get status for task {task_id}:", response.status_code, data or response.text)
            return False
        elif data.get('status') == "SUCCESS":
            print("Task completed successfully")
            return True
        elif data.get('status') != "SUCCESS":
            print(f"Task status is {data.get('status')}, waiting {wait_time} seconds before retrying...")
            time.sleep(wait_time)

def main():

    # vars
    base_url = BASE_URL
    output_path = f'output'  # location to save the CSV file

    #get user report type selection
    print('Enter the option number for the report you would like')
    print('WARNING: The detailed report can be very large for environments with many appliances and large rule count policies')
    print('1) Detailed Report: One line item for every device that hits on a rule')
    print('2) Most Recent Hit Only: One line item per rule, listing only the device with the most recent hit')
    print('3) Zero Hits Only: List only rules that have no hits across all devices')
    report_selection = int(input(': '))
    while report_selection < 1 or report_selection > 3:
        print('Invalid option')
        print('Enter the option number')
        print('1) Detailed Report')
        print('2) Most Recent Hit Only')
        print('3) Zero Hits Only')
        report_selection = int(input(': '))

    #login and retrieve token and DUUID
    result = fmc_login(base_url)
    token = result.get('X-auth-access-token')
    DUUID = result.get('DOMAIN_UUID')

    #get the list of access control policies in FMC
    policies = get_fmc_policies(base_url, token, DUUID)
    if not policies:
        raise Exception("No policies found or error retrieving policies")
    
    # prompt for input on which policy to examine
    print('\nPolicies found')
    for i, item in enumerate(policies, 1):
        print(f"[ {i} ] {item['name']}")
    entry = input('Enter the number of the policy you want to export: ')
    try:
        entry = int(entry)
    except ValueError:
        raise ValueError("Invalid entry: must be a number.")
    if entry < 1 or entry > len(policies):
        raise ValueError("Invalid entry: out of range.")
    policy = policies[entry -1]
    print()

    #get the rules associated with the policy
    print('Gathering policy rules.....')
    rules = get_fmc_rules(base_url, token, DUUID, policy['id'])
    if not rules:
        raise Exception("No rules found or error retrieving rules")

    #get device list
    print('Getting device list....')
    devices = get_devicerecords(base_url, token, DUUID)
    if not devices:
        raise Exception("No devices found or error retrieving devices")
    # filter devices for just those using the selected policy
    devices_filtered = [device for device in devices if device.get("accessPolicy", {}).get("id") == policy['id']]

    #populate rule list dicts with new fields
    print('Initializing objects with new keys....')
    for rule in rules:
        rule['devices'] = [] #list of all devices that hit on a rule
        rule['lastHit'] = '' #timestamp of most recent hit from any device
        rule['lastDevice'] = '' #device name of the most recent hit

    #update rules items with hitcount information
    print(f'Analyzing hit counts on {len(devices_filtered)} devices')
    for device in devices_filtered:
        print(f"Update policy hits for device {device['name']}")
        update = update_policy_hits(base_url, token, DUUID, policy['id'], device['id'])
        if not update:
            print(f"Failed to update policy hits for device {device['name']}. Skipping hit check")
            continue
        print(f"Get policy hits for device {device['name']}")
        hits = get_policy_hits(base_url, token, DUUID, policy['id'], device['id'])
        if not hits:
            print(f"No policy hits found for device {device['name']}. Skipping...")
            continue
        for rule in rules:
            for hit in hits:
                if rule['id'] == hit['rule']['id']:
                    if hit['hitCount'] > 0:
                        device_hit = (device['name'], hit['lastHitTimeStamp'], hit['hitCount'])
                        rule['devices'].append(device_hit)
                        if hit['lastHitTimeStamp'] > rule['lastHit']:
                            rule['lastHit'] = hit['lastHitTimeStamp']
                            rule['lastDevice'] = device['name']
                    break

    #create the report output.  
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    safe_name = "".join(c for c in policy["name"] if c.isalnum() or c in (" ", "_", "-")).rstrip()
    csv_filename = f'FMC-policy-hits-{safe_name}-{timestamp}.csv'
    csv_file = os.path.join(output_path, csv_filename)
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        #detailed report
        if report_selection == 1:
            w.writerow(['Rule ID','Rule Name','Device','Last Hit','Hits'])
            for rule in rules:
                if not rule['devices']:
                    w.writerow([rule.get('metadata', {}).get('ruleIndex', ''), rule['name'], 'NO HITS FOUND', '------', '---'])
                else:
                    for dev, ts, count in rule['devices']:
                        w.writerow([rule.get('metadata', {}).get('ruleIndex', ''), rule['name'], dev, ts, count])

        #most recent hits only
        elif report_selection == 2:
            w.writerow(['Rule ID','Rule Name','Most Recent Device','Last Hit'])
            for rule in rules:
                if rule['lastDevice'] == '':
                    w.writerow([rule.get('metadata', {}).get('ruleIndex', ''), rule['name'], 'NO HITS FOUND', '------'])
                else:
                    w.writerow([rule.get('metadata', {}).get('ruleIndex', ''), rule['name'], rule['lastDevice'], rule['lastHit']])

        #zero hits only
        elif report_selection == 3:
            w.writerow(['Rule ID','Rule Name','Device','Last Hit','Hits'])
            rule_count = 0
            for rule in rules:
                if len(rule['devices']) == 0:
                    w.writerow([rule.get('metadata', {}).get('ruleIndex', ''), rule['name'], 'NO HITS FOUND', '------', '---'])
                    rule_count += 1
            if rule_count == 0:
                w.writerow(['There were no rules found with 0 hits'])

if __name__ == "__main__":
    main()