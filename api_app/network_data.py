from .config import CISCO_BASE_ROUTE_URL, NEUTRON_BASE_URL
import requests

def get_vrf_from_bd(base_tenant, bd_name, cisco_token):
    url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}/BD-{bd_name}.json?query-target=subtree&target-subtree-class=fvRsCtx"
    headers = {
        "Cookie": f"APIC-cookie={cisco_token}"
    }
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        bd_data = response.json().get("imdata", [])

        if not bd_data:
            return "NA"

        vrf_dn = bd_data[0]["fvRsCtx"]["attributes"]["tnFvCtxName"]
        return vrf_dn
    except requests.exceptions.RequestException as e:
        print(f"Error fetching VRF for BD {bd_name}: {e}")
        return "NA"

def network_list(token,base_tenant, cisco_token):
    network_url = f"{NEUTRON_BASE_URL}/networks"
    headers = {"X-Auth-Token": token}
    response = requests.get(network_url, verify=False, headers=headers)

    network_data = response.json().get("networks", [])
    network_data_list = []

    for network in network_data:
        # Extract network information
        network_id = network.get('id')
        network_name = network.get('name')
        network_status = network.get('status')
        is_shared = 'Yes' if network.get('shared') else 'No'
        is_external = 'Yes' if network.get('router:external') else 'No'
        admin_state = 'UP' if network.get('admin_state_up') else 'DOWN'
        subnet_ids = ', '.join(network.get('subnets', []))

        # Fetch segmentation ID
        segmentation_id = get_segmentation_id(token, network_id)

        # Split network name to get base name and construct BD name
        parts = network_name.split('-')
        base_name = '-'.join(parts[:-1]) if len(parts) > 1 else parts[0]
        bd_name = f"{base_name}-bd"

        # Fetch VRF name from BD name
        vrf_name = get_vrf_from_bd(base_tenant, bd_name, cisco_token)

        data = {
            'id': network_id,
            'name': network_name,
            'status': network_status,
            'shared': is_shared,
            'external': is_external,
            'admin_state': admin_state,
            'subnet_ids': subnet_ids,
            'segmentation_id': segmentation_id,
            'vrf_name': vrf_name
        }

        network_data_list.append(data)

    return network_data_list


def get_segmentation_id(token, network_id):
    # Fetch the network details to get the segmentation ID
    network_details_url = f"{NEUTRON_BASE_URL}/networks/{network_id}"
    headers = {"X-Auth-Token": token}
    response = requests.get(network_details_url, verify=False, headers=headers)

    if response.status_code == 200:
        network_details = response.json().get("network", {})
        segmentation_id = network_details.get('provider:segmentation_id', 'N/A')
        return segmentation_id
    else:
        print(f"Failed to fetch details for network ID {network_id}")
        return 'N/A'


def subnet_list(token):
    network_url = f"{NEUTRON_BASE_URL}/subnets"
    headers = {"X-Auth-Token": token}
    y = requests.get(network_url, verify=False, headers=headers)
    subnet_data = y.json().get("subnets")
    subnet_list = []
    for subnet in subnet_data:
        data = {
            'id':  subnet.get("id"),
            'name': subnet.get('name'),
            'network_id': subnet.get('network_id'),
            'cidr': subnet.get('cidr'),
            'gateway_ip': subnet.get('gateway_ip'),
            'ip_version': 'IPv4' if subnet.get('ip_version') == 4 else 'IPv6',
            'enable_dhcp': 'Yes' if subnet.get('enable_dhcp') is True else 'No',
            'start': subnet.get('allocation_pools')[0]['start'] if subnet.get('allocation_pools') else None,
            'end': subnet.get('allocation_pools')[0]['end'] if subnet.get('allocation_pools') else None
        }
        subnet_list.append(data)

    return subnet_list


def bd_list(cisco_token, base_tenant):
    bd_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}.json?query-target=children&target-subtree-class=fvBD"
    bd_data = []
    headers = {
        "Cookie": f"APIC-cookie={cisco_token}"
    }
    bd_response = requests.get(bd_url, headers=headers, verify=False)  # Use the path to your CA certificate

    if bd_response.status_code == 200:
        bd_data_json = bd_response.json().get("imdata", [])

        for bd in bd_data_json:
            bd_ctx = bd.get("fvBD", {}).get("attributes", {})
            name = bd_ctx.get("name")
            type = bd_ctx.get("type")
            seg = bd_ctx.get("seg")
            bcastP = bd_ctx.get("bcastP")
            mac = bd_ctx.get("mac")
            unkMacUcastAct = bd_ctx.get("unkMacUcastAct")
            arpFlood = 'False' if bd_ctx.get("arpFlood") == 'no' else 'True'
            unicastRoute = 'False' if bd_ctx.get("unicastRoute") == 'no' else 'True'

            # Construct query for subnets associated with the BD
            bd_dn = bd.get("fvBD", {}).get("attributes", {}).get("dn", "")
            subnet_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{bd_dn}.json?query-target=subtree&target-subtree-class=fvSubnet"
            subnet_response = requests.get(subnet_url, headers=headers, verify=False)  # Use the path to your CA certificate

            if subnet_response.status_code == 200:
                subnet_data = subnet_response.json().get("imdata", [])
                subnet_ips = [subnet.get("fvSubnet", {}).get("attributes", {}).get("ip") for subnet in subnet_data]
                ip = subnet_ips[0].strip('\'"[]')

            bd_data.append({
                "name": name,
                "type": type,
                "seg": seg,
                "bcastP": bcastP,
                "mac": mac,
                "unkMacUcastAct": unkMacUcastAct,
                "arpFlood": arpFlood,
                "unicastRoute": unicastRoute,
                "ip": ip
            })

    return bd_data



def epg_list(cisco_token, base_tenant):
    epg_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}.json?query-target=subtree&target-subtree-class=fvAEPg"
    epg_data = []

    # Add authentication cookie to headers
    headers = {
        "Cookie": f"APIC-cookie={cisco_token}"
    }
    # Retrieve VRF data
    epg_response = requests.get(epg_url, headers=headers, verify=False)

    # Check VRF data response
    if epg_response.status_code == 200:
        epg_data_json = epg_response.json().get("imdata", [])

        for epg in epg_data_json:
            epg_ctx = epg.get("fvAEPg", {}).get("attributes", {})
            name = epg_ctx.get("name")
            pcTag = epg_ctx.get("pcTag")
            prefGrMemb = epg_ctx.get("prefGrMemb")
            floodOnEncap = epg_ctx.get("floodOnEncap")
            prio = epg_ctx.get("prio")
            pcEnfPref = epg_ctx.get("pcEnfPref")

            epg_data.append({
                "name": name,
                "pcTag": pcTag,
                "prefGrMemb": prefGrMemb,
                "floodOnEncap": floodOnEncap,
                "prio": prio,
                "pcEnfPref": pcEnfPref,

            })
    return epg_data