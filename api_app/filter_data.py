from .config import CISCO_PASS, CISCO_USER, CISCO_AUTH_URL
from .config import KEYSTONE_URL, CISCO_BASE_ROUTE_URL, CISCO_REFRESH_URL, NEUTRON_BASE_URL
from .entry_data import get_entry_details

import requests

def filter_exists(filter_name, base_tenant, cisco_token):
    cisco_headers = {'Cookie': f"APIC-cookie={cisco_token}"}
    filter_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}/flt-{filter_name}.json"
    response = requests.get(filter_url, headers=cisco_headers, verify=False)
    return len(response.json().get('imdata', [])) > 0


def filters_list(cisco_token, base_tenant):
    filters_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}.json?query-target=children&target-subtree-class=vzFilter"
    cisco_headers = {'Cookie': f"APIC-cookie={cisco_token}"}
    response = requests.get(filters_url, headers=cisco_headers, verify=False)
    response.raise_for_status()
    filters = response.json()['imdata']

    filters_data = []
    for filter in filters:
        filter_name = filter['vzFilter']['attributes']['name']
        filter_dn = filter['vzFilter']['attributes']['dn']

        entries = get_entry_details(cisco_token, filter_dn)
        filters_data.append({"filter_name": filter_name, "filter_dn": filter_dn, "entry_names": entries})


    return filters_data



