from .config import CISCO_PASS, CISCO_USER, CISCO_AUTH_URL
from .config import KEYSTONE_URL, CISCO_BASE_ROUTE_URL, CISCO_REFRESH_URL, NEUTRON_BASE_URL

import requests


def l3_out_list(cisco_headers, base_tenant):
    l3_out_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}.json?query-target=children&target-subtree-class=l3extOut&rsp-subtree=full&rsp-subtree-class=bgpExtP,ospfExtP,eigrpExtP,pimExtP,l3extRsEctx"

    l3_out_data = []

    # Send the GET request
    response = requests.get(l3_out_url, headers=cisco_headers, verify=False)

    # Check if the response is successful
    if response.status_code == 200:
        response_data = response.json().get("imdata", [])

        # Loop through each L3 Out profile in the response
        for l3_out in response_data:
            l3_out_attributes = l3_out.get("l3extOut", {}).get("attributes", {})
            l3_out_name = l3_out_attributes.get("name")  # Get the L3 Out profile name
            dn = l3_out_attributes.get("dn")
            tenant_name = ""
            if dn:
                dn_parts = dn.split("/")
                if len(dn_parts) > 1:
                    tenant_name = dn_parts[1].replace("tn-", "")  # Extract tenant name

            # Initialize VRF name (tnFvCtxName)
            vrf_name = ""

            # Look for 'l3extRsEctx' in the children to extract VRF name
            children = l3_out.get("l3extOut", {}).get("children", [])
            for child in children:
                if "l3extRsEctx" in child:
                    vrf_name = child.get("l3extRsEctx", {}).get("attributes", {}).get("tnFvCtxName", "")

            # Append the processed data to the list
            l3_out_data.append({
                "l3_out_name": l3_out_name,
                "tenant_name": tenant_name,
                "vrf_name": vrf_name
            })

        return l3_out_data


def get_node_profiles(cisco_headers, l3out_name, base_tenant):
    node_profile_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}.json?query-target=subtree&target-subtree-class=l3extLNodeP"

    # Fetch Node profiles
    response = requests.get(node_profile_url, headers=cisco_headers, verify=False)

    if response.status_code == 200:
        node_profiles = []
        for item in response.json().get('imdata', []):
            node_name = item.get('l3extLNodeP', {}).get('attributes', {}).get('name')
            targetDscp = item.get('l3extLNodeP', {}).get('attributes', {}).get('targetDscp')
            descr = item.get('l3extLNodeP', {}).get('attributes', {}).get('descr')
            if node_name:
                node_profiles.append({'name': node_name, 'descr': descr, 'targetDscp': targetDscp})

        # Return the node profiles data
        return node_profiles
    else:
        return {'error': 'Failed to fetch Node profiles'}


def get_interface_profiles(cisco_headers, l3out_name, base_tenant, node_profile):
    interface_profile_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}.json?query-target=subtree&target-subtree-class=l3extLIfP"

    # Fetch Interface profiles
    response = requests.get(interface_profile_url, headers=cisco_headers, verify=False)

    if response.status_code == 200:
        interface_profiles = []
        for item in response.json().get('imdata', []):
            interface_name = item.get('l3extLIfP', {}).get('attributes', {}).get('name')
            descr = item.get('l3extLIfP', {}).get('attributes', {}).get('descr')
            if interface_name:
                interface_profiles.append({'name': interface_name, 'descr': descr})
        return interface_profiles
    else:
        return {'error': 'Failed to fetch Interface profiles'}


def get_l3out_leaf_profiles(cisco_headers, l3out_name, node_profile, base_tenant):
    node_profile_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}.json?query-target=subtree&target-subtree-class=l3extRsNodeL3OutAtt"

    # Fetch Node profiles
    response = requests.get(node_profile_url, headers=cisco_headers, verify=False)

    if response.status_code == 200:
        node_ids = []
        for item in response.json().get('imdata', []):
            leaf_profile = item.get('l3extRsNodeL3OutAtt', {}).get('attributes', {}).get('tDn')
            if leaf_profile:
                # Extract the node ID from the tDn (e.g., "topology/pod-1/node-201" -> "node-201")
                node_id = leaf_profile.split('/')[-1]  # Get the last part
                node_ids.append({'leaf_profile': leaf_profile, 'node_id': node_id})
        return node_ids
    else:
        return {'error': 'Failed to fetch Node profiles'}


def get_vrf_list(cisco_headers, base_tenant):
    vrf_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}.json?query-target=children&target-subtree-class=fvCtx"
    vrf_response = requests.get(vrf_url, headers=cisco_headers, verify=False)

    if vrf_response.status_code == 200:
        vrf_data_json = vrf_response.json().get("imdata", [])
        vrf_list = [vrf.get("fvCtx", {}).get("attributes", {}).get("name") for vrf in vrf_data_json]
        return vrf_list
    return []