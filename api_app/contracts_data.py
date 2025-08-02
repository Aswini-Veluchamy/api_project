from .config import CISCO_PASS, CISCO_USER, CISCO_AUTH_URL
from .config import KEYSTONE_URL, CISCO_BASE_ROUTE_URL, CISCO_REFRESH_URL, NEUTRON_BASE_URL
import requests


def contracts_list(cisco_token, base_tenant):

    contracts_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}.json?query-target=children&target-subtree-class=vzBrCP"
    headers = {
        "Cookie": f"APIC-cookie={cisco_token}"
    }
    contract_response = requests.get(contracts_url, headers=headers, verify=False)
    contracts = contract_response.json()['imdata']

    # Collect data for the table
    contracts_data = []
    for contract in contracts:
        contract_name = contract['vzBrCP']['attributes']['name']

        # Get subjects for each contract
        contract_dn = contract['vzBrCP']['attributes']['dn']
        subjects_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{contract_dn}.json?query-target=children&target-subtree-class=vzSubj"
        subject_response = requests.get(subjects_url, headers=headers, verify=False)
        subjects = subject_response.json()['imdata']

        for subject in subjects:
            subject_name = subject['vzSubj']['attributes']['name']
            contracts_data.append({"contract_name": contract_name, "subject_name": subject_name})

    return contracts_data


def contract_exists(contract_name, base_tenant, cisco_token):
    cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}
    contract_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/brc-{contract_name}.json"
    response = requests.get(contract_url, headers=cisco_headers, verify=False)
    return len(response.json().get('imdata', [])) > 0


def subject_exists(subject_name, base_tenant, contract_name, cisco_token):
    cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}
    subject_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/brc-{contract_name}/subj-{subject_name}.json"
    response = requests.get(subject_url, headers=cisco_headers, verify=False)
    return len(response.json().get('imdata', [])) > 0

def get_contracts_epgs(cisco_token, base_tenant):
    epg_url = f"{CISCO_BASE_ROUTE_URL}/node/class/fvAEPg.json"
    cisco_headers = {'Cookie': f"APIC-cookie={cisco_token}"}
    response = requests.get(epg_url, headers=cisco_headers, verify=False)
    epgs = response.json().get('imdata', [])
    return [epg['fvAEPg']['attributes']['dn'] for epg in epgs if base_tenant in epg['fvAEPg']['attributes']['dn']]

