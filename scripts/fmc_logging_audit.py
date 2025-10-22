'''
This script will generate a csv file dump of an access control policy logging settings
In keeping with best practices, deny rules should log at the beginning of the flow
and allow rules should log at the end of the flow.  the output of this script will
aid in a quick audit of the logging settings per the best practice
'''

from datetime import datetime
import csv
import os
from common.fmc_lib import fmc_login, get_fmc_policies, get_fmc_rules
from fmc_config import BASE_URL

# Disable SSL warnings
import urllib3
urllib3.disable_warnings()

def main():

    # vars
    base_url = BASE_URL
    output_path = 'output'  # location to save output file to

    # login and retrieve token and DUUID
    result = fmc_login(base_url)
    token = result.get('X-auth-access-token')
    DUUID = result.get('DOMAIN_UUID')
    
    # get the list of access control policies in FMC
    policies = get_fmc_policies(base_url, token, DUUID)
    if not policies:
        raise Exception("No access control policies retrieved")

    for policy in policies:
        # get the rules associated with the policy
        policy_rules: list[dict] = []
        policy_name = policy.get('name')
        if not policy_name:
            print(f"Policy has no name; skipping")
            continue
        policy_id = policy.get('id')
        if not policy_id:
            print(f"Policy {policy_name} has no id; skipping")
            continue
        violation_counter = 0
        unknown_counter = 0
        rules = get_fmc_rules(base_url, token, DUUID, policy_id)
        if not rules:
            print(f"No rules retrieved for policy {policy_name}.  Skipping")
            continue

        # iterate through the rules, extracting the fields/data i care about, and copy them to a new list of dicts
        for rule in rules:
            rule_name = rule.get('name')
            enabled = rule.get('enabled')
            action = rule.get('action')
            logBegin = rule.get('logBegin')
            logEnd = rule.get('logEnd')

            # if logBegin/logEnd were not retrieved (None) or if they are not proper boolean, 
            # set best practice to UNKNOWN since it could not be determined
            if (action is None or logBegin is None or logEnd is None or
                not isinstance(logBegin, bool) or not isinstance(logEnd, bool)):
                best_practice = 'UNKNOWN'
                print(f'Error accessing logging settings for rule: {rule_name} in policy {policy_name}')
                print(f'Action: {action}, logBegin: {logBegin} type {type(logBegin)}, logEnd: {logEnd} type {type(logEnd)}')
            else:
                a = str(action).upper()
                is_allow = a in ('ALLOW', 'TRUST')
                is_block = 'BLOCK' in a  # matches BLOCK, BLOCK WITH RESET, INTERACTIVE BLOCK, etc.
                if (logBegin is False) and (logEnd is False):
                    best_practice = 'NO'
                    print(f'WARNING: Rule: {rule_name} in policy {policy_name} has logging disabled')
                elif is_allow:
                    best_practice = 'YES' if (logBegin is False and logEnd is True) else 'NO'
                    print(f'WARNING: ALLOW Rule: {rule_name} in policy {policy_name} should log at the end only')
                elif is_block:
                    best_practice = 'YES' if (logBegin is True and logEnd is False) else 'NO'
                    print(f'WARNING: BLOCK Rule: {rule_name} in policy {policy_name} should log at the beginning only')
                else:
                    best_practice = 'UNKNOWN'
                    print(f'WARNING: logging configuration could not be determined for rule: {rule_name} in policy {policy_name}')

            if best_practice == 'NO':
                violation_counter += 1
            elif best_practice == 'UNKNOWN':
                unknown_counter += 1

            policy_rules.append({
                'policy_name': policy_name,
                'enabled': enabled,
                'rule_name': rule_name,
                'action': action,
                'logBegin': logBegin,
                'logEnd': logEnd,
                'best_practice': best_practice,
            })
        
        # final output
        if violation_counter == 0 and unknown_counter == 0:
            print('All rules in policy', policy_name, 'follow best logging practice')

        print("Ensuring output directory exists...")
        # no try, just blow up since there's no point in continuing if this fails
        os.makedirs(output_path, exist_ok=True)
        print(f"Directory '{output_path}' created successfully or already exists.")
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        safe_name = "".join(c for c in policy_name if c.isalnum() or c in (" ", "_", "-")).rstrip()
        output_filename = f'FMC-ACP-{safe_name}-logging-{timestamp}.csv'
        out_file = os.path.join(output_path, output_filename)
        csv_columns = list(dict.fromkeys(k for rule in policy_rules for k in rule.keys()))
        with open(out_file, 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=csv_columns, extrasaction='ignore')
            writer.writeheader()
            for rule in policy_rules:
                writer.writerow(rule)
            print('CSV output for access control policy', policy_name, 'complete')

if __name__ == "__main__":
    main()

