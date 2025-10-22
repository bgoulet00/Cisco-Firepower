import requests
from requests.auth import HTTPBasicAuth
from typing import Optional, List, Dict, Any
import time

TIMEOUT = 30

def fmc_login(base_url: str, user: Optional[str] = None, passwd: Optional[str] = None) -> dict:
    """Login to FMC and retrieve authentication tokens.

    Args:
        base_url (str): The base URL of the FMC API.
    Returns:
        dict: A dictionary containing the authentication tokens and domain UUID.
    """    
    if user is None or passwd is None:
        print('\n\nEnter FMC Credentials')
        user = input("USERNAME: ").strip()
        passwd = input("PASSWORD: ").strip()
    response = requests.post(
       base_url + '/api/fmc_platform/v1/auth/generatetoken',
       auth=HTTPBasicAuth(username=user, password=passwd),
       headers={'content-type': 'application/json'},
       verify=False,
       timeout=TIMEOUT,
    )
    if not response.ok:
        raise Exception(f"Auth failed connecting to {base_url}: {response.status_code} {response.text}")
    access = response.headers.get('X-auth-access-token')
    refresh = response.headers.get('X-auth-refresh-token')
    duuid  = response.headers.get('DOMAIN_UUID')
    if not (access and refresh and duuid):
        raise Exception("Auth succeeded but required headers missing.")
    return {
        'X-auth-access-token': access,
        'X-auth-refresh-token': refresh,
        'DOMAIN_UUID': duuid,
    }

def get_fmc_policies(base_url: str, token: str, DUUID: str) -> Optional[List[Dict[str, Any]]]:
    """Retrieve the list of access control policies in FMC.

    Args:
        base_url (str): The base URL of the FMC API.
        token (str): The authentication token for the FMC API.
        DUUID (str): The domain UUID.
    Returns:
        list: A list of access control policy dictionaries or None.
    """    
    header = {'X-auth-access-token': token,
              'Accept': 'application/json'}
    try:
        response = requests.get(
        base_url + '/api/fmc_config/v1/domain/' + DUUID + '/policy/accesspolicies',
        headers=header,
        verify=False,
        timeout=TIMEOUT,
        )
    except Exception as e:
        print("Error occurred while retrieving policies:", e)
        return None
    if not response.ok:
        print("Failed to retrieve policies:", response.text)
        return None
    data = response.json()
    return data.get('items')

def get_fmc_rules(base_url: str, token: str, DUUID: str, acpID: str) -> Optional[List[Dict[str, Any]]]:
    """get rules associated with an access control policy
    limit is set to 1000
    to support more than 1000 rules, this funtion would require modification to make successive calls, leveraging the 'pages' and 'offset'

    Args:
        base_url (str): The base URL of the FMC API
        token (str): The authentication token
        DUUID (str): The domain UUID
        acpID (str): The access control policy ID
    Returns:
        list: A list of rules (dicts) associated with the access control policy or None
    """   
    try: 
        response = requests.get(
        base_url + '/api/fmc_config/v1/domain/' + DUUID + '/policy/accesspolicies/' + acpID + '/accessrules?limit=1000&expanded=true',
        headers={'X-auth-access-token':token},
        verify=False,
        timeout=TIMEOUT,
        )
    except Exception as e:
        print("Error occurred while retrieving rules:", e)
        return None
    if not response.ok:
        print("Failed to retrieve rules:", response.text)
        return None
    data = response.json()
    return data.get('items')


        