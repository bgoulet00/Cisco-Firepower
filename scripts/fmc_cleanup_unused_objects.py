# this script will identify unused network objects of type Network, Range, Host and Group
# FMC will not allow deletion of objects in use, additionally, this script is only acting on objects marked not in use
# as an additional level of safety, the objects being deleted will be backed up in csv files prior to deletion
# an accompanying script in this project will restore the objects from those backup files if needed 
# it is still recommended that a valid FMC system backup be performed prior to cleanup


import os
import requests
from requests.auth import HTTPBasicAuth
import json
import csv
import sys
import time
from datetime import datetime
from common.fmc_lib import fmc_login
from fmc_config import BASE_URL

# Disable SSL warnings
import urllib3
urllib3.disable_warnings()

def get_net_objects_list(base_url,token, DUUID, objType, unused=False):
    """Retrieve a list of network objects of a specific type from FMC.
    no try/except. if query fails just blow up. no point in continuing

    Args:
        base_url (str): The base URL of the FMC API.
        token (str): The authentication token.
        DUUID (str): The domain UUID.
        objType (str): The type of network object to retrieve (e.g., 'networks', 'hosts').
        unused (bool): If True, retrieve only unused objects. Default is False.
    Returns:
        list: A list of network objects of the specified type.
    """

    objects = []
    limit = 1000
    querystring = {'offset':0,'limit':limit, 'expanded':'true'}
    if unused:
        querystring['filter'] = 'unusedOnly:true'
    headers={'X-auth-access-token':token, 'accept':'application/json'}

    #perform the initial query to determine the number of pages of objects
    response = requests.get(
       base_url + '/api/fmc_config/v1/domain/' + DUUID + '/object/' + objType,
       headers=headers,
       params=querystring,
       verify=False,
    )
    if not response.ok:
        raise Exception(f"Failed to retrieve {objType} objects: {response.text}")
    
    #get the json data and retrieve the value of the page count object
    data = response.json()
    pages = data.get('paging', {}).get('pages', None)
    if pages is None:
        raise Exception("No paging information found in response")

    #query all pages of data
    for page in range(pages):
        querystring['offset'] = page * limit
        response = requests.get(
            base_url + '/api/fmc_config/v1/domain/' + DUUID + '/object/' + objType,
            headers=headers,
            params=querystring,
            verify=False,
        )
        if not response.ok:
            raise Exception(f"Failed to retrieve {objType} objects page {page}: {response.status_code} {response.text}")
        data = response.json()
        for item in data.get('items', []):
            # some objects may be readOnly system objects we can't delete so omit from the list
            if item.get("metadata", {}).get("readOnly", {}).get("state") is not True:
                objects.append(item)

    return objects

def output_objects_to_file(data: dict, fields: list[str], filename: str):
    """Write all dicts from each list in `data` into a single CSV, restricted to `fields`."""
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for key, section in data.items():
            for row in section.get("list", []):
                writer.writerow({field: row.get(field) for field in fields})

def delete_object(base_url, token, DUUID, objType, objID):
    """delete a single object

    Args:
        token (str): The authentication token.
        DUUID (str): The domain UUID.
        objType (str): The type of the object.
        objID (str): The ID of the object.
    Returns:
        bool: True is successfully deleted, otherwise False
    """    
    wait_time = 61
    max_retries = 3
    headers={'X-auth-access-token':token, 'accept':'application/json'}
    for attempt in range(max_retries + 1):
        try:
            response = requests.delete(
            base_url + '/api/fmc_config/v1/domain/' + DUUID + '/object/' + objType + '/' + objID,
            headers=headers,
            verify=False,
            )
        except Exception as e:
            print(f'Error occurred while deleting object: {objType}/{objID}', e)
            return False

        if response.ok:
            return True
        elif response.status_code == 429:
                print(f'request limit reached. pausing {wait_time} seconds')
                time.sleep(wait_time)
                if attempt < max_retries:
                    continue
                print('Max retries reached. Giving up on delete request.')
                return False
        elif response.status_code >= 500:
            time.sleep(2)
            if attempt < max_retries:
                continue
        else:
            print(f'Failed to delete object: {objType}/{objID}, {response.status_code}: {response.text}')
            return False
    return False

def main():

    base_url = BASE_URL
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    output_path = 'output'
    output_filename  = f'fmc-deleted-objects-{timestamp}.csv'
    out_file = os.path.join(output_path, output_filename)
    object_types = ['networks', 'ranges', 'hosts']
    deleted_objects = {}
    dryrun = True

    result = fmc_login(base_url)
    token = result.get('X-auth-access-token')
    DUUID = result.get('DOMAIN_UUID')

    print('\nThis program will identify and optionally delete unused network objects from FMC')
    if input("\nDo you want to delete unused objects? (y/n) ").strip().lower() == 'y':
        dryrun = False
    
    #delete unused groups
    #child groups won't show as unused until partent group is deleted so this section will delete groups in loop
    #until there are no more unused group objects remaining
    deleted_objects['networkgroups'] = {}
    deleted_list = []
    totalGroupsList = get_net_objects_list(base_url, token, DUUID, 'networkgroups')
    unusedGroupsList = get_net_objects_list(base_url, token, DUUID, 'networkgroups', unused=True)
    groups_before = len(totalGroupsList)
    print(f'At least {len(unusedGroupsList)} out of {len(totalGroupsList)} network group objects are unused. There may be more')
    if dryrun:
        print('Dry run, no objects deleted')
        groups_after = groups_before
    else:
        loop_count = 1
        while len(unusedGroupsList) > 0:
            print(f'Deleting objects, pass {loop_count}....')
            for item in unusedGroupsList:
                result = delete_object(base_url, token, DUUID, 'networkgroups', item['id'])
                if not result:
                    print(f"Unable to delete {item['name']}")
                else:
                    deleted_list.append(item)
            unusedGroupsList = get_net_objects_list(base_url, token, DUUID, 'networkgroups', unused=True)
            loop_count += 1
        print('\nGathering updated object information....')
        totalGroupsList = get_net_objects_list(base_url, token, DUUID, 'networkgroups')
        unusedGroupsList = get_net_objects_list(base_url, token, DUUID, 'networkgroups', unused=True)
        groups_after = len(totalGroupsList)
        print(f'{len(unusedGroupsList)} out of {len(totalGroupsList)} network group objects are unused')
    deleted_objects['networkgroups']['count'] = groups_before - groups_after
    deleted_objects['networkgroups']['list'] = deleted_list
    
    #delete unused objects
    for object_type in object_types:
        deleted_objects[object_type] = {}
        deleted_list = []
        print(f'Processing {object_type} objects....')
        total_list = get_net_objects_list(base_url, token, DUUID, object_type)
        unused_list = get_net_objects_list(base_url, token, DUUID, object_type, unused=True)
        count_before = len(total_list)
        print(f'{len(unused_list)} out of {len(total_list)} {object_type} objects are unused')
        if dryrun:
            print('Note: There may be additional items that are members of unused groups.  Unused groups need to be removed before those members will be marked unused')
            print('Dry run, no objects deleted')
            count_after = count_before
        else:
            print('Deleting objects....')
            for item in unused_list:
                result = delete_object(base_url, token, DUUID, object_type, item['id'])
                if not result:
                    print(f"Unable to delete {item['name']}")
                else:
                    deleted_list.append(item)
            print('\nGathering updated object information....')
            total_list = get_net_objects_list(base_url, token, DUUID, object_type)
            unused_list = get_net_objects_list(base_url, token, DUUID, object_type, unused=True)
            count_after = len(total_list)
            print(f'{len(unused_list)} out of {len(total_list)} {object_type} objects are unused')
        deleted_objects[object_type]['count'] = count_before - count_after
        deleted_objects[object_type]['list'] = deleted_list
    
    #summary output
    for key, value in deleted_objects.items():
        print(f"{key} objects removed: {value.get('count', 0)}")

    output_columns = ["type", "name", "description", "value"]
    output_objects_to_file(deleted_objects, output_columns, out_file)

if __name__ == "__main__":
    main()
