from .config import CISCO_PASS, CISCO_USER, CISCO_AUTH_URL
from .config import KEYSTONE_URL, CISCO_BASE_ROUTE_URL, CISCO_REFRESH_URL, NEUTRON_BASE_URL

import requests

def get_epgs(cisco_token):
    url = f"{CISCO_BASE_ROUTE_URL}/node/class/fvAEPg.json"
    headers = {
        "Cookie": f"APIC-cookie={cisco_token}"
    }
    response = requests.get(url, headers=headers, verify=False)
    return response.json()["imdata"]


def get_contracts(cisco_token, base_tenant):
    url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}.json?query-target=children&target-subtree-class=vzBrCP"
    headers = {
        "Cookie": f"APIC-cookie={cisco_token}"
    }
    response = requests.get(url, headers=headers, verify=False)
    return response.json()["imdata"]


def fetch_ap_epg_contract_data(cisco_token, base_tenant):
    # Fetch APs and their EPGs
    aps = []
    aps_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}.json?query-target=children&target-subtree-class=fvAp"
    headers = {'Cookie': f"APIC-cookie={cisco_token}"}
    response = requests.get(aps_url, headers=headers, verify=False)
    ap_data = response.json().get('imdata', [])

    for ap in ap_data:
        ap_name = ap['fvAp']['attributes']['name']
        ap_dn = ap['fvAp']['attributes']['dn']

        # Fetch EPGs for this AP
        epgs = []
        epg_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}/ap-{ap_name}.json?query-target=subtree&target-subtree-class=fvAEPg"
        response = requests.get(epg_url, headers=headers, verify=False)
        epg_data = response.json().get('imdata', [])

        for epg in epg_data:
            epg_name = epg['fvAEPg']['attributes']['name']
            epg_dn = epg['fvAEPg']['attributes']['dn']

            # Fetch contracts for this EPG
            contracts = []
            contracts_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{epg_dn}.json?query-target=subtree&target-subtree-class=fvRsCons,fvRsProv"
            response = requests.get(contracts_url, headers=headers, verify=False)
            contract_data = response.json().get('imdata', [])

            for contract in contract_data:
                if 'fvRsCons' in contract:
                    contract_type = 'Consumer'
                    state = contract['fvRsCons']['attributes']['state']
                    contract_dn = contract['fvRsCons']['attributes']['tDn']
                elif 'fvRsProv' in contract:
                    contract_type = 'Provider'
                    state = contract['fvRsProv']['attributes']['state']
                    contract_dn = contract['fvRsProv']['attributes']['tDn']

                # Assuming you fetch contract name from contract_dn or any other logic
                contract_name = contract_dn.split('/')[-1][4:]  # Example logic to extract contract name

                contracts.append({
                    'contract_type': contract_type,
                    'contract_dn': contract_dn,
                    'contract_name': contract_name,
                    'state': state
                })

            epgs.append({
                'epg_name': epg_name,
                'epg_dn': epg_dn,
                'contracts': contracts
            })

        aps.append({
            'ap_name': ap_name,
            'ap_dn': ap_dn,
            'epgs': epgs
        })

    return aps


def get_contracts_epgs(cisco_token, base_tenant):
    epg_url = f"{CISCO_BASE_ROUTE_URL}/node/class/fvAEPg.json"
    headers = {'Cookie': f"APIC-cookie={cisco_token}"}
    response = requests.get(epg_url, headers=headers, verify=False)
    epgs = response.json()['imdata']
    return [epg['fvAEPg']['attributes']['dn'] for epg in epgs if base_tenant in epg['fvAEPg']['attributes']['dn']]

def get_contracts_for_epg(cisco_token, epg_dn):
    contracts_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{epg_dn}.json?query-target=subtree&target-subtree-class=fvRsCons,fvRsProv"
    headers = {'Cookie': f"APIC-cookie={cisco_token}"}
    response = requests.get(contracts_url, headers=headers, verify=False)
    contracts = response.json()['imdata']
    contract_list = []
    for contract in contracts:
        if 'fvRsCons' in contract:
            contract_list.append({'contract_type': 'Consumer', 'contract_dn': contract['fvRsCons']['attributes']['tDn']})
        elif 'fvRsProv' in contract:
            contract_list.append({'contract_type': 'Provider', 'contract_dn': contract['fvRsProv']['attributes']['tDn']})
    return contract_list


def verify_epg_exists(ap_name, epg_name, cisco_headers):
    url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-development/ap-{ap_name}.json?query-target=children&target-subtree-class=fvAEPg"

    response = requests.get(url, headers=cisco_headers, verify=False)

    if response.status_code == 200:
        data = response.json()
        # Check if the EPG exists in the list of children under the AP
        for child in data.get('imdata', []):
            if 'fvAEPg' in child and child['fvAEPg']['attributes']['name'] == epg_name:
                return True
    return False


def verify_contract_exists(base_tenant, contract_name, cisco_headers):
    contracts_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}.json?query-target=children&target-subtree-class=vzBrCP"
    contract_response = requests.get(contracts_url, headers=cisco_headers, verify=False)
    if contract_response.status_code == 200:
        data = contract_response.json()
        for child in data.get('imdata', []):
            if 'vzBrCP' in child and child['vzBrCP']['attributes']['name'] == contract_name:
                return True
    return False