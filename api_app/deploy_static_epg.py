from .config import CISCO_PASS, CISCO_USER, CISCO_AUTH_URL
from .config import KEYSTONE_URL, CISCO_BASE_ROUTE_URL, CISCO_REFRESH_URL, NEUTRON_BASE_URL

import requests

def colo_epg_list(cisco_headers, ap_name, base_tenant):
    epg_list = []

    epg_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}/ap-{ap_name}.json?query-target=subtree&target-subtree-class=fvAEPg"
    epg_response = requests.get(epg_url, headers=cisco_headers, verify=False)

    if epg_response.status_code == 200:
        epg_data_json = epg_response.json().get("imdata", [])
        epg_list.extend([epg.get("fvAEPg", {}).get("attributes", {}).get("name") for epg in epg_data_json])

    return epg_list


def get_epg_interfaces(cisco_headers, node_id, base_tenant):
    epg_interfaces = []

    url = f"https://172.31.231.91/api/node/class/topology/pod-1/{node_id}/l1PhysIf.json?rsp-subtree=children&rsp-subtree-class=ethpmPhysIf"
    response = requests.get(url, headers=cisco_headers, verify=False)
    response.raise_for_status()

    # Print the response for debugging
    node_details = response.json().get('imdata', [])

    for interface in node_details:
        # Check if 'l1PhysIf' key exists in the interface
        if 'l1PhysIf' in interface and 'children' in interface['l1PhysIf']:
            for child in interface['l1PhysIf']['children']:
                if 'ethpmPhysIf' in child:
                    # Fetch attributes
                    attributes = child['ethpmPhysIf']['attributes']
                    usage = attributes.get('usage', '')
                    description = interface['l1PhysIf']['attributes'].get('descr', '')
                    if description == base_tenant:
                        id = interface['l1PhysIf']['attributes'].get('id', '')

                        if id:  # Ensure ID is not empty
                            epg_interfaces.append({'id': id, 'name': f"{node_id}"})

    return epg_interfaces


def get_vlan_epg_details(cisco_headers, aep_name):
    url = f"https://172.31.231.91/api/node/mo/uni/infra/attentp-{aep_name}/gen-default.json?query-target=children&target-subtree-class=infraRsFuncToEpg"

    response = requests.get(url, headers=cisco_headers, verify=False)
    response.raise_for_status()
    data = response.json().get('imdata', [])

    epg_details = []
    for item in data:
        if 'infraRsFuncToEpg' in item:
            attributes = item['infraRsFuncToEpg']['attributes']
            tDn = attributes.get('tDn', '')
            encap = attributes.get('encap', '')
            epg_name = tDn.split('/epg-')[-1]
            epg_details.append({'epg_name': epg_name, 'encap': encap})

    return epg_details


def get_ap_list(cisco_headers, base_tenant):
    ap_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}.json?query-target=children&target-subtree-class=fvAp"
    ap_response = requests.get(ap_url, headers=cisco_headers, verify=False)

    if ap_response.status_code == 200:
        ap_data_json = ap_response.json().get("imdata", [])
        ap_list = [ap.get("fvAp", {}).get("attributes", {}).get("name") for ap in ap_data_json]
        return ap_list
    return []


def get_aep_name_for_epg(cisco_headers, tenant, ap_name, epg_name):
    import requests

    # Step 1: Get domain attached to EPG
    epg_url = f"https://172.31.231.91/api/node/mo/uni/tn-{tenant}/ap-{ap_name}/epg-{epg_name}.json"
    params = {
        "query-target": "children",
        "target-subtree-class": "fvRsDomAtt"
    }

    response = requests.get(epg_url, headers=cisco_headers, params=params, verify=False)
    response.raise_for_status()

    epg_domains = [
        item["fvRsDomAtt"]["attributes"]["tDn"]
        for item in response.json().get("imdata", [])
        if "fvRsDomAtt" in item
    ]

    if not epg_domains:
        return None

    # Step 2: Find AEPs that reference any of these domains
    aep_url = "https://172.31.231.91/api/node/mo/uni/infra.json"
    aep_params = {
        "query-target": "subtree",
        "target-subtree-class": "infraRsDomP"
    }
    response = requests.get(aep_url, headers=cisco_headers, params=aep_params, verify=False)
    response.raise_for_status()

    aep_entries = response.json().get("imdata", [])

    for item in aep_entries:
        if "infraRsDomP" in item:
            attributes = item["infraRsDomP"]["attributes"]
            domain_dn = attributes.get("tDn")
            aep_dn = attributes.get("dn")

            if domain_dn in epg_domains:
                for part in aep_dn.split("/"):
                    if part.startswith("attentp-"):
                        aep_name = part.replace("attentp-", "")
                        return aep_name

    return None
