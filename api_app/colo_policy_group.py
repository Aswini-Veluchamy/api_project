from .config import CISCO_PASS, CISCO_USER, CISCO_AUTH_URL
from .config import KEYSTONE_URL, CISCO_BASE_ROUTE_URL, CISCO_REFRESH_URL, NEUTRON_BASE_URL

import requests

def get_all_policy_groups(cisco_headers, base_tenant):
    # URLs to fetch leaf_access and vpc policy groups
    leaf_access_url = f"{CISCO_BASE_ROUTE_URL}/node/class/infraAccPortGrp.json"
    vpc_url = f"{CISCO_BASE_ROUTE_URL}/node/class/infraAccBndlGrp.json"

    # Retrieve leaf_access Policy Groups data
    leaf_access_response = requests.get(leaf_access_url, headers=cisco_headers, verify=False)
    vpc_response = requests.get(vpc_url, headers=cisco_headers, verify=False)

    leaf_access_policy_groups = []
    vpc_policy_groups = []

    # Check leaf_access Policy Groups response
    if leaf_access_response.status_code == 200:
        leaf_access_policy_groups_json = leaf_access_response.json().get("imdata", [])
        # Preprocess leaf_access Policy Groups data
        for group in leaf_access_policy_groups_json:
            group_attrs = group.get("infraAccPortGrp", {}).get("attributes", {})
            name = group_attrs.get("name")
            descr = group_attrs.get("descr")
            dn = group_attrs.get("dn")
            if base_tenant in name:
                leaf_access_policy_groups.append({
                    "name": name,
                    "descr": descr,
                    "dn": dn
                })

    # Check vpc Policy Groups response
    if vpc_response.status_code == 200:
        vpc_policy_groups_json = vpc_response.json().get("imdata", [])
        # Preprocess vpc Policy Groups data
        for group in vpc_policy_groups_json:
            group_attrs = group.get("infraAccBndlGrp", {}).get("attributes", {})
            name = group_attrs.get("name")
            descr = group_attrs.get("descr")
            dn = group_attrs.get("dn")
            if base_tenant in name:
                vpc_policy_groups.append({
                    "name": name,
                    "descr": descr,
                    "dn": dn
            })

    # Return both leaf_access and vpc policy groups
    return {
        "leaf_access_policy_groups": leaf_access_policy_groups,
        "vpc_policy_groups": vpc_policy_groups
    }


def policy_group_exists(cisco_headers, policy_group_name, profile_type):
    if profile_type == 'Individual':
        url = f"{CISCO_BASE_ROUTE_URL}/node/class/infraAccPortGrp.json"
    elif profile_type == 'Bond':
        url = f"{CISCO_BASE_ROUTE_URL}/node/class/infraAccBndlGrp.json"
    else:
        return False

    response = requests.get(url, headers=cisco_headers, verify=False)

    if response.status_code == 200:
        data = response.json().get("imdata", [])
        names = [item['infraAccPortGrp']['attributes']['name'] for item in data] if profile_type == 'Individual' else [item['infraAccBndlGrp']['attributes']['name'] for item in data]
        return policy_group_name in names