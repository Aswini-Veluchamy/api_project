import requests
import re

def get_leaf_node_ids(cisco_headers):
    url = "https://172.31.231.91/api/node/class/topology/pod-1/l1PhysIf.json"
    response = requests.get(url, headers=cisco_headers, verify=False)
    response.raise_for_status()
    imdata = response.json().get('imdata', [])

    # Extract all node IDs
    filtered_node_ids = sorted({
        f"{dn_parts[2]}"  # Extract the node ID in the format "node-<number>"
        for interface in imdata
        if 'l1PhysIf' in interface
        if (dn := interface['l1PhysIf']['attributes'].get('dn', ''))  # Get DN attribute
        if len(dn.split('/')) > 2  # Ensure there are enough parts in the DN
        for dn_parts in [dn.split('/')]  # Split DN into parts
    })

    # Nodes to be excluded
    exclude_nodes = {'node-501', 'node-502'}

    # Filter out the excluded node IDs
    all_node_ids = [node for node in filtered_node_ids if node not in exclude_nodes]

    # Separate odd node IDs
    odd_node_ids = [node for node in all_node_ids if int(node.split('-')[-1]) % 2 == 1]

    return all_node_ids, odd_node_ids


def get_node_details(cisco_headers, node_id, base_tenant):
    node_details = []

    url = f"https://172.31.231.91/api/node/class/topology/pod-1/{node_id}/l1PhysIf.json?rsp-subtree=children&rsp-subtree-class=ethpmPhysIf"
    response = requests.get(url, headers=cisco_headers, verify=False)
    response.raise_for_status()
    data = response.json().get('imdata', [])

    for interface in data:
        if 'children' in interface['l1PhysIf']:
            for child in interface['l1PhysIf']['children']:
                if 'ethpmPhysIf' in child:
                    # Fetch interface attributes
                    ethpm_attributes = child['ethpmPhysIf']['attributes']
                    l1_phys_attributes = interface['l1PhysIf']['attributes']
                    interface_id = l1_phys_attributes.get('id', '')

                    # Filter based on description matching base_tenant
                    if l1_phys_attributes.get('descr') == base_tenant:
                        node_details.append({
                            'id': interface_id,
                            'usage': 'Free' if ethpm_attributes.get('usage') == "discovery" else 'Allocated',
                            'description': l1_phys_attributes.get('descr', ''),
                            'operSt': ethpm_attributes.get('operSt', ''),
                            'operStQual': ethpm_attributes.get('operStQual', ''),
                        })

    # Sort node_details based on the 'id' field numerically
    def extract_numeric_id(id_str):
        # Extract all numbers from the id string
        numbers = re.findall(r'\d+', id_str)
        # Combine numbers to create a sortable numeric value
        return int(''.join(numbers)) if numbers else 0

    node_details.sort(key=lambda x: extract_numeric_id(x['id']))

    return node_details


def get_unused_interfaces(cisco_headers, node_id, base_tenant):
    unused_interfaces = []

    url = f"https://172.31.231.91/api/node/class/topology/pod-1/{node_id}/l1PhysIf.json?rsp-subtree=children&rsp-subtree-class=ethpmPhysIf"
    response = requests.get(url, headers=cisco_headers, verify=False)
    response.raise_for_status()
    node_details = response.json().get('imdata', [])

    for interface in node_details:
        # Check if the 'ethpmPhysIf' child class exists
        if 'children' in interface['l1PhysIf']:
            for child in interface['l1PhysIf']['children']:
                if 'ethpmPhysIf' in child:
                    # Fetch attributes
                    attributes = child['ethpmPhysIf']['attributes']
                    usage = attributes.get('usage', '')
                    description = interface['l1PhysIf']['attributes'].get('descr', '')
                    if usage == 'discovery' and description == base_tenant:
                        id = interface['l1PhysIf']['attributes'].get('id', '')
                        if id:  # Ensure id is not empty
                            unused_interfaces.append(id)

    return unused_interfaces


def is_policy_group_already_used(cisco_headers, vpc_policy_groups):
    url = f"https://172.31.231.91/api/node/mo/uni/infra/funcprof/accbundle-{vpc_policy_groups}.json?query-target=children&target-subtree-class=relnFrom"
    try:
        response = requests.get(url, headers=cisco_headers, verify=False)
        response.raise_for_status()
        return len(response.json().get('imdata', [])) > 0
    except requests.RequestException as e:
        print(f"Error checking policy group usage: {e}")
        return False


def get_all_leaf_profiles(cisco_headers):
    url = 'https://172.31.231.91/api/node/class/infraAccPortP.json'
    response = requests.get(url, headers=cisco_headers, verify=False)
    response.raise_for_status()
    leaf_profiles = response.json().get('imdata', [])

    profile_names = []
    for item in leaf_profiles:
        profile_name = item['infraAccPortP']['attributes'].get('name')
        if profile_name and '_' in profile_name:  # Only include names with '_'
            # Remove the "-IntProf" suffix if present
            if profile_name.endswith('-IntProf'):
                profile_name = profile_name[:-len('-IntProf')]
            profile_names.append(profile_name)

    return profile_names


def get_policy_groups(cisco_headers, profile_name, base_tenant):
    url = f"https://172.31.231.91/api/node/mo/uni/infra/accportprof-{profile_name}.json?query-target=subtree&target-subtree-class=infraHPortS&target-subtree-class=infraPortBlk,infraRsAccBaseGrp"
    response = requests.get(url, headers=cisco_headers, verify=False)
    response.raise_for_status()
    data = response.json().get("imdata", [])

    rs_acc_base_grp_data = []
    profile_description_map = {}

    # First, map all HPortS dn to their descriptions
    for item in data:
        if "infraHPortS" in item:
            attributes = item["infraHPortS"]["attributes"]
            dn = attributes.get("dn", "")
            descr = attributes.get("descr", "")
            profile_description_map[dn] = descr

    # Process RsAccBaseGrp and filter by matching HPortS description
    for item in data:
        if "infraRsAccBaseGrp" in item:
            attributes = item["infraRsAccBaseGrp"]["attributes"]
            dn = attributes["dn"]
            hport_dn = "/".join(dn.split('/')[:-1])  # Parent DN of RsAccBaseGrp is HPortS

            descr = profile_description_map.get(hport_dn, "")
            if descr != base_tenant:
                continue  # Skip if description doesn't match exactly

            dn_parts = dn.split('/')[-2]
            dn_parts1 = dn.split('/')[-3]
            if dn_parts1.startswith('accportprof-'):
                profile_name = dn_parts1.split('-IntProf')[0]

            tdn = attributes["tDn"].split('/')[-1]
            if 'accbundle' in tdn:
                tdn = tdn.split('accbundle-')[1]
            elif 'accportgrp' in tdn:
                tdn = tdn.split('accportgrp-')[1]
            else:
                tdn = None

            rs_acc_base_grp_data.append({
                'dn': dn_parts.split('-')[1],
                'profile_name': profile_name.split('accportprof-')[1],
                'tdn': tdn,
                'descr': descr  # Include matching description
            })

    # Add fromPort/fromCard info
    for item in data:
        if "infraPortBlk" in item:
            attributes = item["infraPortBlk"]["attributes"]
            from_port = attributes["fromPort"]
            from_card = attributes["fromCard"]
            for entry in rs_acc_base_grp_data:
                if entry['dn'] in attributes["dn"]:
                    entry['fromPort'] = from_port
                    entry['fromCard'] = from_card

    return rs_acc_base_grp_data


