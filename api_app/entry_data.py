from .config import CISCO_PASS, CISCO_USER, CISCO_AUTH_URL
from .config import KEYSTONE_URL, CISCO_BASE_ROUTE_URL, CISCO_REFRESH_URL, NEUTRON_BASE_URL

import requests

def entry_exists(filter_name, entry_name, base_tenant, cisco_token):
    headers = {
        "Cookie": f"APIC-cookie={cisco_token}"
    }
    entry_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}/flt-{filter_name}/e-{entry_name}.json"
    response = requests.get(entry_url, headers=headers, verify=False)
    return len(response.json().get('imdata', [])) > 0

def get_entry_details(cisco_token, filter_dn):
    cisco_headers = {'Cookie': f"APIC-cookie={cisco_token}"}
    entries_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{filter_dn}.json?query-target=children&target-subtree-class=vzEntry"
    response = requests.get(entries_url, headers=cisco_headers, verify=False)
    entries = []
    if response.status_code == 200:
        entries_json = response.json().get("imdata", [])
        for entry in entries_json:
            entry_ctx = entry.get("vzEntry", {}).get("attributes", {})
            entries.append({
                "entry_name": entry_ctx.get("name"),
                "prot": entry_ctx.get("prot"),
                "Destination": entry_ctx.get("dToPort")
            })
    return entries

def entry_details(base_tenant, filter_name, cisco_headers):
    entries_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}/flt-{filter_name}.json?query-target=children&target-subtree-class=vzEntry"
    response = requests.get(entries_url, headers=cisco_headers, verify=False)

    entries = []
    if response.status_code == 200:
        entries_json = response.json().get("imdata", [])
        for entry in entries_json:
            entry_ctx = entry.get("vzEntry", {}).get("attributes", {})
            entries.append({
                "entry_name": entry_ctx.get("name"),
                "etherT": entry_ctx.get("etherT"),
                "prot": entry_ctx.get("prot"),
                'stateful': True if entry_ctx.get('stateful') == 'yes' else False,
                "dFromPort": entry_ctx.get("dFromPort"),
                "dToPort": entry_ctx.get("dToPort")
            })
    return entries