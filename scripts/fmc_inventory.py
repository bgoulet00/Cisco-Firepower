# this script will will generate an output file FTD-device-list.csv containing the appliance inventory managed by FMC
# FMC misreports the serial number of the appliances.  to obtain the serial associated with support contracts it will be queried
# directly from the cli of the appliance and extracted using regular expression. this technique currently only works on FTD
# appliances, not ASA running FTD code

import requests
from requests.auth import HTTPBasicAuth
import csv
import sys
from paramiko.client import SSHClient, AutoAddPolicy
import re
import os
from fmc_config import BASE_URL
from common.fmc_lib import fmc_login

# Disable SSL warnings
import urllib3
urllib3.disable_warnings()

def get_devicerecords(token, DUUID):
    """Retrieve device records from FMC.

    Args:
        token (str): The authentication token.
        DUUID (str): The domain UUID.

    Returns:
        dict: A dictionary containing the device records.
    """    

    #query paramaters to control results limit and offset. 1000 is max limit
    limit = str(1000)
    offset = str(0)
    querystring = {'offset':offset,'limit':limit}
    
    #perform the query
    response = requests.get(
       BASE_URL + '/api/fmc_config/v1/domain/' + DUUID + '/devices/devicerecords?expanded=true',
       headers={'X-auth-access-token':token},
       params=querystring,
       verify=False,
    )
    
    data = response.json()
    return data


def main():

    output_path = 'output'
    output_filename = 'FTD-device-list.csv'
    devicerecords_outfile = os.path.join(output_path, output_filename)

    devices = []
    outfile_columns = ['name', 'hostName', 'model', 'serial', 'sw_version', 'deviceGroup', 'id']
    
    #there is an assumption that FMC and FTD login credentials are the same and only requested once
    print('\n\nEnter Firepower Credentials')
    user = input("USERNAME: ").strip()
    passwd = input("PASSWORD: ").strip()
    result = fmc_login(BASE_URL, user, passwd)
    token = result.get('X-auth-access-token')
    DUUID = result.get('DOMAIN_UUID')
    
    #get standard device info available in FMC
    print('\nGathering data from FMC.....')
    devicerecords = get_devicerecords(token, DUUID)
    for item in devicerecords['items']:
        device = {'name':item['name'], 'hostName':item['hostName'], 'model':item['model'], 'sw_version':item['sw_version'], 'deviceGroup':item['deviceGroup']['name'], 'id':item['id']}
        devices.append(device)
    
    #FMC lies about device serial number.  the serial number associated with the support contract
    #can only be obtained from the FTD cli.  SSH to each appliance cli to grab the serial
    #for some reason ssh to FTD puts you in fxos mode rather than ftd mode so the show command is an fxos command
    #this direct SSH query only works on FTD appliances, not ASA devices running firepower
    #FTD appliances are very slow to intially connect with ssh, causing this code section to run slow
    print('Gathering serial numbers from appliances.....')
    for device in devices:
        print('Querying', device['name'], '...')
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy)
        try:
            ssh.connect(device['hostName'], 22, username=user, password=passwd)
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("show chassis inventory")
            raw_output = ssh_stdout.read().decode()
            # extract serial number using regular expression
            matches = re.search('([A-Z]{3}[A-Z,0-9]{8})', raw_output)
            if matches:
                serial = matches.group(0)
            else:
                serial = 'UNKNOWN'
            device['serial'] = serial
        except Exception as e:
            print(f'ERROR: Could not connect to {device["name"]}, {e}')
            device['serial'] = 'UNKNOWN'
        finally:
            ssh.close()

    
    #create output inventory file
    with open(devicerecords_outfile, "w", newline='') as file:
        writer = csv.DictWriter(file, fieldnames=outfile_columns)
        writer.writeheader()
        for device in devices:
            writer.writerow(device)
        
if __name__ == "__main__":
    main()