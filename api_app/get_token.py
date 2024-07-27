import requests
from .config import CISCO_PASS, CISCO_USER, CISCO_AUTH_URL
from .config import KEYSTONE_URL, CISCO_BASE_ROUTE_URL, CISCO_REFRESH_URL, NEUTRON_BASE_URL

def get_cisco_token():
    login_data = {
        "aaaUser": {
            "attributes": {
                "name": CISCO_USER,
                "pwd": CISCO_PASS
            }
        }
    }
    login_response = requests.post(CISCO_AUTH_URL, json=login_data, verify=False)

    if login_response.status_code == 200:
        token = login_response.json()['imdata'][0]['aaaLogin']['attributes']['token']
        return token
    else:
        raise Exception('Failed to retrieve Cisco token. Please check user details.')

def refresh_cisco_token(token):
    headers = {"Cookie": f"APIC-cookie={token}"}
    refresh_response = requests.post(CISCO_REFRESH_URL, headers=headers, verify=False)

    if refresh_response.status_code == 200:
        new_token = refresh_response.json()['imdata'][0]['aaaLogin']['attributes']['token']
        return new_token
    else:
        raise Exception('Failed to refresh Cisco token.')

def get_openstack_token(username, password, domain):
    url = KEYSTONE_URL
    myobj = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "domain": {"name": domain},
                        "password": password
                    }
                }
            }
        }
    }
    x = requests.post(url, json=myobj, verify=False)
    token = ''
    tenant_list = []

    if x.status_code == 201:
        token = x.headers["X-Subject-Token"]
        project_json = x.json().get("token", {}).get("project")
        if project_json:
            tenant_list.append(project_json.get("name"))
    return x.status_code, token, tenant_list

def get_vrf_list(token, base_tenant):
    vrf_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}.json?query-target=children&target-subtree-class=fvCtx"
    headers = {"Cookie": f"APIC-cookie={token}"}
    vrf_response = requests.get(vrf_url, headers=headers, verify=False)

    if vrf_response.status_code == 200:
        vrf_data_json = vrf_response.json().get("imdata", [])
        vrf_list = [vrf.get("fvCtx", {}).get("attributes", {}).get("name") for vrf in vrf_data_json]
        return vrf_list
    return []

def get_bd_list(token, base_tenant):
    bd_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}.json?query-target=children&target-subtree-class=fvBD"
    headers = {"Cookie": f"APIC-cookie={token}"}
    bd_response = requests.get(bd_url, headers=headers, verify=False)

    if bd_response.status_code == 200:
        bd_data_json = bd_response.json().get("imdata", [])
        bd_list = [bd.get("fvBD", {}).get("attributes", {}).get("name") for bd in bd_data_json]
        return bd_list
    return []

def get_ap_list(token, base_tenant):
    ap_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}.json?query-target=children&target-subtree-class=fvAp"
    headers = {"Cookie": f"APIC-cookie={token}"}
    ap_response = requests.get(ap_url, headers=headers, verify=False)

    if ap_response.status_code == 200:
        ap_data_json = ap_response.json().get("imdata", [])
        ap_list = [ap.get("fvAp", {}).get("attributes", {}).get("name") for ap in ap_data_json]
        return ap_list
    return []


def get_epg_list(token, base_tenant):
    epg_list = []
    headers = {"Cookie": f"APIC-cookie={token}"}
    ap_list = get_ap_list(token, base_tenant)

    for ap in ap_list:
        epg_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}/ap-{ap}.json?query-target=subtree&target-subtree-class=fvAEPg"
        epg_response = requests.get(epg_url, headers=headers, verify=False)

        if epg_response.status_code == 200:
            epg_data_json = epg_response.json().get("imdata", [])
            epg_list.extend([epg.get("fvAEPg", {}).get("attributes", {}).get("name") for epg in epg_data_json])
    return epg_list

def get_bd_subnet_data(token):
    bd_url = f"{CISCO_BASE_ROUTE_URL}/node/class/fvSubnet.json"
    headers = {"Cookie": f"APIC-cookie={token}"}
    bd_response = requests.get(bd_url, headers=headers, verify=False)
    subnet_data = {}

    if bd_response.status_code == 200:
        bd_data_json = bd_response.json().get("imdata", [])
        subnet_data = {bd.get("fvSubnet", {}).get("attributes", {}).get('uid'): bd.get("fvSubnet", {}).get("attributes", {}).get('ip') for bd in bd_data_json}
    return subnet_data

def get_physical_domains(token):
    phy_url = f"{CISCO_BASE_ROUTE_URL}/node/class/physDomP.json"
    headers = {"Cookie": f"APIC-cookie={token}"}
    phy_response = requests.get(phy_url, headers=headers, verify=False)

    if phy_response.status_code == 200:
        phy_data_json = phy_response.json().get("imdata", [])
        phy_list = [phy.get("physDomP", {}).get("attributes", {}).get("name") for phy in phy_data_json]
        return phy_list
    return []

def get_access_policies(token):
    pol_url = f"{CISCO_BASE_ROUTE_URL}/node/class/infraAttEntityP.json"
    headers = {"Cookie": f"APIC-cookie={token}"}
    pol_response = requests.get(pol_url, headers=headers, verify=False)

    if pol_response.status_code == 200:
        pol_data_json = pol_response.json().get("imdata", [])
        pol_list = [pol.get("infraAttEntityP", {}).get("attributes", {}).get("name") for pol in pol_data_json]
        return pol_list
    return []


def check_physical_domain(token, domain_name):
    domains = get_physical_domains(token)
    if domain_name in domains:
        return domain_name
    else:
        return None


def create_bd(bd_name, vrf_name, base_tenant, gateway_ip, cidr, cisco_token):
    payload = {
        "fvBD": {
            "attributes": {
                "name": bd_name
            },
            "children": [
                {
                    "fvRsCtx": {
                        "attributes": {
                            "tnFvCtxName": vrf_name
                        }
                    }
                },
                {
                    "fvSubnet": {
                        "attributes": {
                            "ip": f"{gateway_ip}/{cidr}"
                        }
                    }
                }
            ]
        }
    }
    url = f"https://172.31.1.11/api/node/mo/uni/tn-{base_tenant}.json"
    response = create_resource(cisco_token, url, payload)
    print(f"create_bd response: {response.status_code}, {response.text}")
    return response

def create_epg(ap_name, epg_name, bd_name, cisco_token, base_tenant):
    payload = {
        "fvAEPg": {
            "attributes": {
                "name": epg_name
            },
            "children": [
                {
                    "fvRsBd": {
                        "attributes": {
                            "tnFvBDName": bd_name
                        }
                    }
                }
            ]
        }
    }
    url = f"https://172.31.1.11/api/node/mo/uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}.json"
    response = create_resource(cisco_token, url, payload)
    print(f"create_epg response: {response.status_code}, {response.text}")
    return response

def attach_phy_domain(ap_name, epg_name, phys_domain_name, base_tenant, cisco_token):
    payload = {
        "fvRsDomAtt": {
            "attributes": {
                "resImedcy": "immediate",
                "tDn": f"uni/phys-{phys_domain_name}",
                "status": "created"
            },
            "children": []
        }
    }
    url = f"https://172.31.1.11/api/node/mo/uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}/rsdomAtt-[uni/phys-{phys_domain_name}].json"
    response = create_resource(cisco_token, url, payload)
    print(f"attach_phy_domain response: {response.status_code}, {response.text}")
    return response

def attach_aep(ap_name, epg_name, aep_name, vlan, base_tenant, cisco_token):
    payload = {
        "infraRsFuncToEpg": {
            "attributes": {
                "tDn": f"uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}",
                "status": "created,modified",
                "encap": f"vlan-{vlan}"
            },
            "children": []
        }
    }
    url = f"https://172.31.1.11/api/node/mo/uni/infra/attentp-{aep_name}/gen-default.json"
    response = create_resource(cisco_token, url, payload)
    print(f"attach_aep response: {response.status_code}, {response.text}")
    return response


def create_resource(cisco_token, url, payload):
    headers = {"Cookie": f"APIC-cookie={cisco_token}"}
    response = requests.post(url, headers=headers, json=payload, verify=False)
    response.raise_for_status()
    return response


def create_openstack_network(token, network_name, admin_state, mtu):
    headers = {"X-Auth-Token": token}
    network_data = {
        'network': {
            'name': network_name,
            'admin_state_up': admin_state,
            'provider:network_type': 'vlan',
            'provider:physical_network': 'dcfabric',
            'mtu': mtu
        }
    }
    network_url = f"{NEUTRON_BASE_URL}/networks"
    network_response = requests.post(network_url, json=network_data, verify=False, headers=headers)

    if network_response.status_code != 201:
        return None, None

    network_id = network_response.json()['network']['id']
    segment_id = network_response.json()['network'].get('provider:segmentation_id')
    return network_id, segment_id


def create_subnet(network_id, subnet_ip, subnet_name, gateway_ip, token):
    headers = {"X-Auth-Token": token}
    subnet_data = {
        "subnet": {
            "network_id": network_id,
            "cidr": subnet_ip,
            "ip_version": 4,
            "name": subnet_name,
            "gateway_ip": gateway_ip
        }
    }
    subnet_url = f"{NEUTRON_BASE_URL}/subnets"
    subnet_response = requests.post(subnet_url, headers=headers, json=subnet_data, verify=False)

    if subnet_response.status_code != 201:
        return None

    subnet_id = subnet_response.json()['subnet']['id']
    return subnet_id

def delete_network(network_id, token):
    headers = {"X-Auth-Token": token}
    delete_network_url = f"{NEUTRON_BASE_URL}/networks/{network_id}"
    delete_response = requests.delete(delete_network_url, headers=headers, verify=False)
    if delete_response.status_code != 204:
        print(f"Failed to delete network: {delete_response.text}")

