from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import requests
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#AUTHENTICATION

from .config import CISCO_BASE_ROUTE_URL, NEUTRON_BASE_URL
from .utils import user_login, token_required, get_cisco_token

#ZONE
from .zone_data import vrf_list, ap_list
#NETWORK
from .get_token import check_physical_domain, get_access_policies, get_bd_list, get_epg_list
from .get_token import create_bd, create_epg, attach_phy_domain, attach_aep, is_vlan_within_range
from .get_token import create_openstack_network, create_subnet, delete_network_for_subnet
from .network_data import network_list, subnet_list
#CONTRACTS
from .contracts_data import contracts_list, contract_exists, subject_exists, get_contracts_epgs
from .subjects_data import list_filters
#FILTERS
from .filter_data import filter_exists, filters_list
from .entry_data import entry_exists, entry_details
#CONTRACT MAPPING
from .contract_mapping import get_epgs, get_contracts, get_contracts_for_epg
from .contract_mapping import fetch_ap_epg_contract_data, verify_epg_exists, verify_contract_exists
#SECURITY GROUP and SECURITY GROUP RULE
from .security_group import security_group_list, security_group_rules_list
#COLO POLICY GROUP
from .colo_policy_group import get_all_policy_groups, policy_group_exists
#COLO ACCESS PORT
from .colo_access_port import get_node_details, get_leaf_node_ids, get_all_leaf_profiles
from .colo_access_port import get_unused_interfaces
from .colo_access_port import get_policy_groups, is_policy_group_already_used
#COLO STATIC EPG
from .deploy_static_epg import colo_epg_list, get_epg_interfaces, get_vlan_epg_details, get_ap_list, \
    get_aep_name_for_epg
#L3OUT
from .l3out import l3_out_list, get_vrf_list, get_node_profiles
from .l3out import get_interface_profiles, get_l3out_leaf_profiles, get_fabric_path_eps, l3out_vlan_pool_check


############################################
############### USER LOGIN #################
############################################

@method_decorator(csrf_exempt, name='dispatch')
class UserLogin(APIView):
    def post(self, request):
        domain = request.data.get('domain')
        username = request.data.get('username')
        password = request.data.get('password')

        if domain and username and password:
            status_code, token = user_login(domain, username, password)
            if not status_code:
                return Response({'message': 'Please Provide Valid Details!!!'}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({'token': token}, status=status.HTTP_200_OK)
        return Response({'message': 'Please Provide Username,Domain and Passsword Details'},
                        status=status.HTTP_400_BAD_REQUEST)


############################################
################## ZONE ####################
############################################

class Zones(APIView):
    @method_decorator(token_required)
    def get(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        vrf_data = vrf_list(cisco_token, base_tenant)
        print(vrf_data)
        ap_data = ap_list(cisco_token, base_tenant)

        return Response({'vrf_data': vrf_data, 'ap_data': ap_data}, status=status.HTTP_200_OK)

    @method_decorator(token_required)
    def post(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        zone_name = request.data.get("zone_name")
        base_tenant = user.get('tenant_list')[0]

        if not request.data:
            return Response({'status': 'error', 'message': 'Request body is empty.'})

        if not all([cisco_token, zone_name, base_tenant]):
            return Response({'status': 'error', 'message': 'Missing required parameters'})

        vrf_zone_name = f"{base_tenant}-{zone_name}-vrf"
        ap_zone_name = f"{base_tenant}-{zone_name}-ap"

        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        vrf_data = vrf_list(cisco_token, base_tenant)
        ap_data = ap_list(cisco_token, base_tenant)
        if vrf_zone_name in [i.get('name') for i in vrf_data] or ap_zone_name in [i.get('name') for i in ap_data]:
            messages = 'Zone already exists with same name'
            return Response({'status': 'error', "message": messages})

        # Create VRF
        vrf_payload = {
            "fvCtx": {
                "attributes": {
                    "name": vrf_zone_name
                }
            }
        }
        vrf_creation_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}.json"
        vrf_response = requests.post(vrf_creation_url, headers=cisco_headers, json=vrf_payload, verify=False)

        if vrf_response.status_code == 200:
            # Create AP
            ap_payload = {
                "fvAp": {
                    "attributes": {
                        "name": ap_zone_name
                    }
                }
            }
            ap_creation_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}.json"
            ap_response = requests.post(ap_creation_url, headers=cisco_headers, json=ap_payload, verify=False)

            if ap_response.status_code == 200:
                messages = f"Zone created successfully - {vrf_zone_name}"
                return Response({'status': 'success', "message": messages})
            else:
                # Rollback Zone creation if AP creation fails
                rollback_vrf_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/ctx-{vrf_zone_name}.json"
                requests.delete(rollback_vrf_url, headers=cisco_headers, verify=False)
                messages = f"Failed to create Zone"
                return Response({'status': 'error', "message": messages})
        else:
            messages = f"Failed to create Zone"
            return Response({'status': 'error', "message": messages})


############################################
################# NETWORK ##################
############################################

class Network(APIView):
    @method_decorator(token_required)
    def get(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        token = request.user.get('openstack_token')
        base_tenant = user.get('tenant_list')[0]
        network_data = network_list(token, base_tenant, cisco_token)
        subnet_data = subnet_list(token)
        return Response({'network_data': network_data, 'subnet_data': subnet_data}, status=status.HTTP_200_OK)

    @method_decorator(token_required)
    def post(self, request):
        cisco_token = get_cisco_token()
        token = request.user.get('openstack_token')
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        network = request.data.get("network_name")
        vrf_name = request.data.get("vrf")
        mtu = request.data.get("mtu")
        subnet_ip = request.data.get("subnet_ip")
        gateway_ip = request.data.get("gateway_ip")
        _, cidr = subnet_ip.split('/')
        admin_state = request.data.get("admin_state")

        if not request.data:
            return Response({'status': 'error', 'message': 'Request body is empty.'})

        if not all([token, network, vrf_name, mtu, subnet_ip, gateway_ip, admin_state, base_tenant]):
            return Response({'status': 'error', 'message': 'Missing required parameters'})

        # Splitting VRF name for AP
        parts = vrf_name.split('-')
        base_name = '-'.join(parts[:-1]) if len(parts) > 1 else parts[0]

        ap_name = f"{base_name}-ap"
        network_name = f"{base_tenant}-{network}-nw"
        subnet_name = f"{base_tenant}-{network}-sub"
        bd_name = f"{base_tenant}-{network}-bd"
        epg_name = f"{base_tenant}-{network}-epg"

        # Check the physical domain and access policies available in Cisco
        phys_domain_name = check_physical_domain(cisco_token, f"{base_tenant}-phy-domain")
        if not phys_domain_name:
            messages = 'No Physical domain are available'
            return Response({'status': 'error', 'messages': messages})

        # Check bd_name and epg_name
        bd_list_flag = get_bd_list(cisco_token, base_tenant)
        epg_list_flag = get_epg_list(cisco_token, base_tenant)
        network_flag = any(network['name'] == network_name for network in network_list(token, base_tenant, cisco_token))
        subnet_flag = any(subnet['name'] == subnet_name for subnet in subnet_list(token))

        if bd_name in bd_list_flag or epg_name in epg_list_flag or network_flag or subnet_flag:
            messages = 'Network already exists with the same name'
            return Response({'status': 'error', 'messages': messages})

        # Create network in OpenStack
        network_id, segment_id = create_openstack_network(token, network_name, admin_state, mtu)
        if not network_id:
            messages = "Failed to create Network"
            return Response({'status': 'error', 'messages': messages})

        if not segment_id:
            delete_network_for_subnet(network_id, token)
            messages = "Failed to create Network: Segment ID not retrieved."
            return Response({'status': 'error', 'messages': messages})

        # VLAN segment ID validation
        cookies = {'APIC-cookie': cisco_token}
        if not is_vlan_within_range(segment_id, base_tenant, cookies):
            delete_network_for_subnet(network_id, token)
            messages = f"VLAN {segment_id} is not within the range of available VLANs"
            return Response({'status': 'error', 'messages': messages})

        # Continue with subnet creation
        subnet_id = create_subnet(network_id, subnet_ip, subnet_name, gateway_ip, token)
        if not subnet_id:
            delete_network_for_subnet(network_id, token)
            messages = "Failed to create Network"
            return Response({'status': 'error', 'messages': messages})

        # Creating BD and EPG in Cisco ACI
        bd_response = create_bd(bd_name, vrf_name, base_tenant, gateway_ip, cidr, cisco_token)
        epg_response = create_epg(ap_name, epg_name, bd_name, cisco_token, base_tenant)
        phy_dmn_response = attach_phy_domain(ap_name, epg_name, phys_domain_name, base_tenant, cisco_token)
        aep_response = attach_aep(ap_name, epg_name, f"development_AEP_HPServers", segment_id, base_tenant, cisco_token)

        if all(response.status_code == 200 for response in [bd_response, epg_response, phy_dmn_response, aep_response]):
            messages = "Network created successfully"
            return Response({'status': 'success', 'messages': messages})
        else:
            messages = "Failed to create Network"
            return Response({'status': 'error', 'messages': messages})

    @method_decorator(token_required)
    def put(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        token = request.user.get('openstack_token')
        base_tenant = user.get('tenant_list')[0]
        network_id = request.data.get('network_id')
        new_admin_state = request.data.get('admin_state')

        if not request.data:
            return Response({'status': 'error', 'message': 'Request body is empty.'})

        if not all([cisco_token, network_id, new_admin_state, base_tenant]):
            return Response({'status': 'error', 'message': 'Missing required parameters'})

        headers = {"X-Auth-Token": token}

        network_data = {
            'network': {
                'admin_state_up': new_admin_state,
            }
        }
        network_url = f"https://neutron.tcsecp.com:9696/v2.0/networks/{network_id}"
        response = requests.put(network_url, json=network_data, verify=False, headers=headers)

        if response.status_code == 200:
            return Response({'status': 'success', 'message': 'Admin state updated successfully'})
        else:
            return Response({'status': 'error', 'message': 'Failed to update admin state'})

    @method_decorator(token_required)
    def delete(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        token = request.user.get('openstack_token')
        base_tenant = user.get('tenant_list')[0]
        network_id = request.data.get('network_id')
        network_name = request.data.get('network_name')
        vrf_name = request.data.get('vrf')

        if not request.data:
            return Response({'status': 'error', 'message': 'Request body is empty.'})

        if not all([token, network_id, network_name, vrf_name, base_tenant]):
            return Response({'status': 'error', 'message': 'Missing required parameters'})

        # Splitting network name to get base name
        parts = network_name.split('-')
        base_name = '-'.join(parts[:-1]) if len(parts) > 1 else parts[0]
        bd_name = f"{base_name}-bd"
        epg_name = f"{base_name}-epg"

        vrf_parts = vrf_name.split('-')
        vrf_base_name = '-'.join(vrf_parts[:-1]) if len(vrf_parts) > 1 else vrf_parts[0]
        ap_name = f"{vrf_base_name}-ap"

        bd_list_flag = get_bd_list(cisco_token, base_tenant)
        epg_list_flag = get_epg_list(cisco_token, base_tenant)
        network_flag = any(network['id'] == network_id for network in network_list(token, base_tenant, cisco_token))

        if bd_name not in bd_list_flag or epg_name not in epg_list_flag or not network_flag:
            return Response({'status': 'error',
                             'message': 'Unable to find the network or associated resources, contact administrator'})

        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        headers = {"X-Auth-Token": token}

        # Delete Network
        delete_network_url = f"https://neutron.tcsecp.com:9696/v2.0/networks/{network_id}"
        delete_network_response = requests.delete(delete_network_url, headers=headers, verify=False)

        if delete_network_response.status_code == 204:
            # Delete Bridge Domain
            bd_dn = f"uni/tn-{base_tenant}/BD-{bd_name}"
            delete_bd_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/BD-{bd_name}.json"
            bd_payload = {
                "fvBD": {
                    "attributes": {
                        "dn": bd_dn,
                        "status": "deleted"
                    },
                    "children": []
                }
            }
            delete_bd_response = requests.post(delete_bd_url, headers=cisco_headers, json=bd_payload, verify=False)

            # Delete EPG
            epg_dn = f"uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}"
            delete_epg_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}.json"
            epg_payload = {
                "fvAEPg": {
                    "attributes": {
                        "dn": epg_dn,
                        "status": "deleted"
                    },
                    "children": []
                }
            }
            delete_epg_response = requests.post(delete_epg_url, headers=cisco_headers, json=epg_payload, verify=False)

            # Delete VLAN
            vlan_dn = f"uni/infra/attentp-development_AEP_HPServers/gen-default/rsfuncToEpg-[uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}]"
            delete_vlan_url = f"https://172.31.231.91/api/node/mo/uni/infra/attentp-development_AEP_HPServers/gen-default/rsfuncToEpg-[uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}].json"
            vlan_payload = {
                "infraRsFuncToEpg": {
                    "attributes": {
                        "dn": vlan_dn,
                        "status": "deleted"
                    },
                    "children": []
                }
            }
            delete_vlan_response = requests.post(delete_vlan_url, headers=cisco_headers, json=vlan_payload,
                                                 verify=False)

            # Check if any delete operations failed
            if (delete_bd_response.status_code == 200
                    and delete_epg_response.status_code == 200 and delete_vlan_response.status_code == 200):
                return Response({'status': 'success', 'message': 'Network deleted successfully'})
            else:
                error_message = f'Failed to delete network.'
                return Response({'status': 'error', 'message': error_message})
        else:
            error_message = f'Failed to delete network.'
            return Response({'status': 'error', 'message': error_message})


############################################
################ CONTRACTS #################
############################################

class Contracts(APIView):
    @method_decorator(token_required)
    def get(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        contracts_data = contracts_list(cisco_token, base_tenant)

        return Response({'contracts_data': contracts_data}, status=status.HTTP_200_OK)

    @method_decorator(token_required)
    def post(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        name = request.data.get("name")
        filter_name = request.data.get("filter_name")

        if not request.data:
            return Response({'status': 'error', 'message': 'Request body is empty.'})

        if not all([cisco_token, name, filter_name, base_tenant]):
            return Response({'status': 'error', 'message': 'Missing required parameters'})

        contract_name = f"{base_tenant}-{name}-con"
        subject_name = f"{base_tenant}-{name}-sub"

        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        if contract_exists(contract_name, base_tenant, cisco_token) or subject_exists(subject_name, base_tenant,
                                                                                      contract_name,
                                                                                      cisco_token):
            messages = 'Contract already exists with the same name'
            return Response({'status': 'error', 'message': messages})

        # Create Contract
        contract_payload = {
            "vzBrCP": {
                "attributes": {
                    "dn": f"uni/tn-{base_tenant}/brc-{contract_name}",
                    "name": contract_name,
                    "scope": "context",
                    "status": "created"
                }
            }
        }
        contract_creation_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/brc-{contract_name}.json"
        contract_response = requests.post(contract_creation_url, headers=cisco_headers, json=contract_payload,
                                          verify=False)

        if contract_response.status_code == 200:
            # Create Subject
            subject_payload = {
                "vzSubj": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/brc-{contract_name}/subj-{subject_name}",
                        "name": subject_name,
                        "status": "created"
                    }
                }
            }
            subject_creation_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/brc-{contract_name}/subj-{subject_name}.json"
            subject_response = requests.post(subject_creation_url, headers=cisco_headers, json=subject_payload,
                                             verify=False)

            if subject_response.status_code == 200:
                subject_filter_payload = {
                    "vzRsSubjFiltAtt": {
                        "attributes": {
                            "tnVzFilterName": filter_name,
                            "status": "created"
                        }
                    }
                }
                subject_filter_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/brc-{contract_name}/subj-{subject_name}.json"
                subject_filter_response = requests.post(subject_filter_url, headers=cisco_headers,
                                                        json=subject_filter_payload, verify=False)

                if subject_filter_response.status_code == 200:
                    messages = f"Contract created successfully"
                    return Response({'status': 'success', 'message': messages})
                else:
                    messages = f"Failed to attach filter"
                    return Response({'status': 'error', 'message': messages})

            else:
                messages = f"Failed to create Subject"
        else:
            messages = f"Failed to create Contract"

        return Response({'status': 'error', 'message': messages})

    @method_decorator(token_required)
    def delete(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        contract_name = request.data.get('contract_name')

        if not request.data:
            return Response({'status': 'error', 'message': 'Request body is empty.'})

        if not all([cisco_token, contract_name, base_tenant]):
            return Response({'status': 'error', 'message': 'Missing required parameters'})

        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        if not contract_name:
            return Response({'status': 'error', 'error': 'Contract name not provided.'})

        if not contract_exists(contract_name, base_tenant, cisco_token):
            messages = 'Contract does not exists'
            return Response({'status': 'error', 'message': messages})

        contract_dn = f"uni/tn-{base_tenant}/brc-{contract_name}"
        epgs_with_contracts = get_contracts_epgs(cisco_token, base_tenant)

        for epg_dn in epgs_with_contracts:
            prov_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{epg_dn}.json?query-target=subtree&target-subtree-class=fvRsProv"
            cons_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{epg_dn}.json?query-target=subtree&target-subtree-class=fvRsCons"

            prov_response = requests.get(prov_url, headers=cisco_headers, verify=False)
            cons_response = requests.get(cons_url, headers=cisco_headers, verify=False)

            if prov_response.status_code == 200:
                prov_data = prov_response.json().get('imdata', [])
                for prov in prov_data:
                    if prov['fvRsProv']['attributes']['tDn'] == contract_dn:
                        return Response({'status': 'error',
                                         'message': 'Contract is mapped to an EPG (provider) and cannot be deleted.'})

            if cons_response.status_code == 200:
                cons_data = cons_response.json().get('imdata', [])
                for cons in cons_data:
                    if cons['fvRsCons']['attributes']['tDn'] == contract_dn:
                        return Response({'status': 'error',
                                         'message': 'Contract is mapped to an EPG (consumer) and cannot be deleted.'})

        delete_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{contract_dn}.json"
        payload = {
            "vzBrCP": {
                "attributes": {
                    "dn": contract_dn,
                    "status": "deleted"
                },
                "children": []
            }
        }

        delete_response = requests.post(delete_url, headers=cisco_headers, json=payload, verify=False)
        if delete_response.status_code == 200:
            return Response({'status': 'success', 'message': 'Contract deleted successfully'})
        else:
            return Response({'status': 'error', 'message': 'Failed to delete contract.'})


############################################
################# SUBJECTS #################
############################################

class SubjectHandler(APIView):
    @method_decorator(token_required)
    def get(self, request, contract_name):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        sub_name = contract_name.split('-')[1]
        subject_name = f"{base_tenant}-{sub_name}-sub"
        filter_list = list_filters(contract_name, subject_name, cisco_token, base_tenant)

        return Response({"filter_list": filter_list}, status=status.HTTP_200_OK)

    @method_decorator(token_required)
    def post(self, request, contract_name):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        filter_name = request.data.get("filter_name")
        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        if not request.data:
            return Response({'status': 'error', 'message': 'Request body is empty.'})

        if not all([cisco_token, contract_name, filter_name, base_tenant]):
            return Response({'status': 'error', 'message': 'Missing required parameters'})

        sub_name = contract_name.split('-')[1]
        subject_name = f"{base_tenant}-{sub_name}-sub"

        update_subject_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/brc-{contract_name}/subj-{subject_name}.json"

        payload = {
            "vzSubj": {
                "attributes": {
                    "dn": f"uni/tn-{base_tenant}/brc-{contract_name}/subj-{subject_name}",
                    "name": subject_name,
                },
                "children": [
                    {
                        "vzRsSubjFiltAtt": {
                            "attributes": {
                                "tnVzFilterName": filter_name,
                                "status": "created,modified"
                            }
                        }
                    }
                ]
            }
        }

        response = requests.post(update_subject_url, json=payload, headers=cisco_headers, verify=False)

        if response.status_code == 200:
            messages = f"Filter added to subject successfully"
            return Response({'status': 'success', 'message': messages})
        else:
            messages = f"Failed to add filter to subject"
            return Response({'status': 'error', 'message': messages})

    @method_decorator(token_required)
    def delete(self, request, contract_name):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        filter_name = request.data.get('filter_name')
        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        if not request.data:
            return Response({'status': 'error', 'message': 'Request body is empty.'})

        if not all([cisco_token, contract_name, filter_name, base_tenant]):
            return Response({'status': 'error', 'message': 'Missing required parameters'})

        sub_name = contract_name.split('-')[1]
        subject_name = f"{base_tenant}-{sub_name}-sub"

        if not contract_exists(contract_name, base_tenant, cisco_token):
            messages = 'Contract does not exist'
            return Response({'status': 'error', 'message': messages})

        filters = list_filters(contract_name, subject_name, cisco_token, base_tenant)
        filter_names = [filt['filter_name'] for filt in filters]

        if filter_name not in filter_names:
            messages = 'Filter does not exist in this subject'
            return Response({'status': 'error', 'message': messages})

        delete_subject_filter_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/brc-{contract_name}/subj-{subject_name}/rssubjFiltAtt-{filter_name}.json"
        payload = {
            "vzRsSubjFiltAtt": {
                "attributes": {
                    "dn": f"uni/tn-{base_tenant}/brc-{contract_name}/subj-{subject_name}/rssubjFiltAtt-{filter_name}",
                    "status": "deleted"
                },
                "children": []
            }
        }

        response = requests.post(delete_subject_filter_url, json=payload, headers=cisco_headers, verify=False)

        if response.status_code == 200:
            messages = f"Filter deleted successfully"
            return Response({'status': 'success', 'message': messages})
        else:
            messages = f"Failed to delete Filter"
            return Response({'status': 'error', 'message': messages})


############################################
################# FILTERS ##################
############################################

class Filters(APIView):
    @method_decorator(token_required)
    def get(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        filters_data = filters_list(cisco_token, base_tenant)

        return Response({"filters_data": filters_data}, status=status.HTTP_200_OK)

    @method_decorator(token_required)
    def post(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        name = request.data.get("name")
        filter_name = f"{base_tenant}-{name}-flt"

        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        if filter_exists(filter_name, base_tenant, cisco_token):
            return Response({'status': 'error', 'message': 'Filter already exists with the same name'})

        # Construct the filter payload
        filter_payload = {
            "vzFilter": {
                "attributes": {
                    "dn": f"uni/tn-{base_tenant}/flt-{filter_name}",
                    "name": filter_name,
                    "status": "created"
                }
            }
        }

        # Construct the filter creation URL
        filter_creation_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/flt-{filter_name}.json"

        # Make the API request to create the filter
        filter_response = requests.post(filter_creation_url, headers=cisco_headers, json=filter_payload, verify=False)

        if filter_response.status_code == 200:
            return Response({'status': 'success', 'message': f"Filter created successfully"})
        else:
            return Response({'status': 'error', 'message': f"Failed to create Filter"})

    @method_decorator(token_required)
    def delete(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        name = request.data.get("name")
        filter_name = f"{base_tenant}-{name}-flt"

        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        if not filter_exists(filter_name, base_tenant, cisco_token):
            return Response({'status': 'error', 'message': 'Filter not exists'})

        delete_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/flt-{filter_name}.json"
        payload = {
            "vzFilter": {
                "attributes": {
                    "dn": f"uni/tn-{base_tenant}/flt-{filter_name}",
                    "status": "deleted"
                },
                "children": []
            }
        }

        response = requests.post(delete_url, headers=cisco_headers, json=payload, verify=False)

        if response.status_code == 200:
            return Response({'status': 'success', 'message': f"Filter deleted successfully"})
        else:
            return Response({'status': 'error', 'message': f"Failed to deleted Filter"})


############################################
################## ENTRY ###################
############################################

class EntryHandler(APIView):
    @method_decorator(token_required)
    def get(self, request, filter_name):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        entries = entry_details(base_tenant, filter_name, cisco_headers)

        return Response({"entries": entries}, status=status.HTTP_200_OK)

    @method_decorator(token_required)
    def post(self, request, filter_name):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        entry_name = request.data.get('entry_name')
        prot = request.data.get('prot')
        dFromPort = request.data.get('dFromPort')
        dToPort = request.data.get('dToPort')

        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        if entry_exists(filter_name, entry_name, base_tenant, cisco_token):
            return Response({'status': 'error', 'message': 'Entry already exists with the same name'})

        # Construct the entry payload
        entry_payload = {
            "vzEntry": {
                "attributes": {
                    "dn": f"uni/tn-{base_tenant}/flt-{filter_name}/e-{entry_name}",
                    "name": entry_name,
                    "etherT": "ip",
                    "prot": prot
                }
            }
        }

        if prot != "icmp":
            entry_payload["vzEntry"]["attributes"]["stateful"] = "yes"
            entry_payload["vzEntry"]["attributes"]["dFromPort"] = dFromPort
            entry_payload["vzEntry"]["attributes"]["dToPort"] = dToPort
        else:
            entry_payload["vzEntry"]["attributes"]["stateful"] = "no"

        # Send the request to add the entry
        entry_creation_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/flt-{filter_name}.json"

        entry_response = requests.post(entry_creation_url, headers=cisco_headers, json=entry_payload, verify=False)

        if entry_response.status_code == 200:
            return Response({'status': 'success', 'message': f"Entry added successfully"})
        else:
            return Response({'status': 'error', 'message': f"Failed to add Entry"})

    @method_decorator(token_required)
    def delete(self, request, filter_name):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        entry_id = request.data.get("entry_id")

        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        if not entry_id:
            return Response({'status': 'error', 'error': 'Entry ID is required'})

        delete_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/flt-{filter_name}/e-{entry_id}.json"
        payload = {
            "vzEntry": {
                "attributes": {
                    "dn": f"uni/tn-{base_tenant}/flt-{filter_name}/e-{entry_id}",
                    "status": "deleted"
                },
                "children": []
            }
        }

        response = requests.post(delete_url, headers=cisco_headers, json=payload, verify=False)

        if response.status_code == 200:
            return Response({'status': 'success', 'message': f"Filter deleted successfully"})
        else:
            return Response({'status': 'error', 'message': f"Failed to deleted Filter"})


############################################
############# CONTRACT MAPPING #############
############################################

class ContractMapping(APIView):
    @method_decorator(token_required)
    def get(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]

        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        epgs = get_epgs(cisco_token)
        # Exact tenant name
        base_epgs = [epg['fvAEPg']['attributes'] for epg in epgs if
                     epg['fvAEPg']['attributes']['dn'].startswith(f"uni/tn-{base_tenant}") and
                     (epg['fvAEPg']['attributes']['dn'] == f"uni/tn-{base_tenant}" or
                      epg['fvAEPg']['attributes']['dn'][len(f"uni/tn-{base_tenant}")] == '/')]
        epg_names = [
            (epg['dn'], epg['dn'].split('/')[1], epg['dn'].split('/')[2],
             epg['dn'].split('/')[3].replace('epg-', ''))
            for epg in base_epgs
        ]

        contracts = get_contracts(cisco_token, base_tenant)
        contract_names = [contract['vzBrCP']['attributes']['name'] for contract in contracts]

        epgs = get_contracts_epgs(cisco_token, base_tenant)
        epg_contracts = []

        for epg_dn in epgs:
            contracts = get_contracts_for_epg(cisco_token, epg_dn)
            epg_contracts.append({
                'epg_dn': epg_dn,
                'epg_name': epg_dn.split('/')[-1],  # Assuming the EPG name is the last part of the DN
                'contracts': contracts
            })

        # Fetch APs, EPGs, and contracts
        aps = fetch_ap_epg_contract_data(cisco_token, base_tenant)

        #return Response({'epg_names': epg_names, 'contract_names': contract_names, 'epg_contracts': epg_contracts, 'aps': aps}, status=status.HTTP_200_OK)
        return Response({'aps': aps}, status=status.HTTP_200_OK)

    @method_decorator(token_required)
    def post(self, request):
        # Retrieve the Cisco token and user details
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]

        # Retrieve the data from the request
        provider_ap = request.data.get('provider_ap')
        provider_epg = request.data.get('provider_epg')
        consumer_ap = request.data.get('consumer_ap')
        consumer_epg = request.data.get('consumer_epg')
        contract_name = request.data.get('contract_name')
        directional = request.data.get('directional')

        # Check if all required parameters are provided
        if not all([provider_epg, provider_ap, consumer_epg, consumer_ap, contract_name, directional]):
            return Response(
                {'status': 'error', 'message': 'Missing required parameters'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Construct EPG Distinguished Names (DN)
        provider_epg_dn = f"uni/tn-{base_tenant}/ap-{provider_ap}/epg-{provider_epg}"
        consumer_epg_dn = f"uni/tn-{base_tenant}/ap-{consumer_ap}/epg-{consumer_epg}"

        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        # Verify if provider EPG exists under the specified AP
        if not verify_epg_exists(provider_ap, provider_epg, cisco_headers):
            return Response(
                {'status': 'error', 'message': f'Provider EPG "{provider_epg}" not found in AP "{provider_ap}".'}
            )

        # Verify if consumer EPG exists under the specified AP
        if not verify_epg_exists(consumer_ap, consumer_epg, cisco_headers):
            return Response(
                {'status': 'error', 'message': f'Consumer EPG "{consumer_epg}" not found in AP "{consumer_ap}".'}
            )

        if provider_epg_dn == consumer_epg_dn:
            return Response(
                {'status': 'error', 'message': f"Consumer EPG and Provider EPG should not be same"}
            )

        if not verify_contract_exists(base_tenant, contract_name, cisco_headers):
            return Response(
                {'status': 'error', 'message': f'Contract does not exists'}
            )

        # Handle the directional logic
        if directional == "uni":
            # Prepare the provider payload
            provider_payload = {
                "fvRsProv": {
                    "attributes": {
                        "tnVzBrCPName": contract_name,
                        "status": "created,modified"
                    },
                    "children": []
                }
            }
            provider_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{provider_epg_dn}.json"

            response = requests.post(provider_url, json=provider_payload, headers=cisco_headers, verify=False)

            if response.status_code != 200:
                return Response(
                    {'status': 'error', 'message': f"Failed to map provider EPG to contract"}
                )

            # Map consumer EPG to contract
            consumer_payload = {
                "fvRsCons": {
                    "attributes": {
                        "tnVzBrCPName": contract_name,
                        "status": "created,modified"
                    },
                    "children": []
                }
            }
            consumer_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{consumer_epg_dn}.json"

            response = requests.post(consumer_url, json=consumer_payload, headers=cisco_headers, verify=False)

            if response.status_code != 200:
                return Response(
                    {'status': 'error', 'message': f"Failed to map consumer EPG to contract"}
                )

        elif directional == "bi":
            # Prepare the provider payload
            provider_payload = {
                "fvRsProv": {
                    "attributes": {
                        "tnVzBrCPName": contract_name,
                        "status": "created,modified"
                    },
                    "children": []
                }
            }
            provider_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{provider_epg_dn}.json"

            response = requests.post(provider_url, json=provider_payload, headers=cisco_headers, verify=False)

            if response.status_code != 200:
                return Response(
                    {'status': 'error', 'message': f"Failed to map provider EPG to contract"}
                )

            # Map consumer EPG to contract
            consumer_payload = {
                "fvRsCons": {
                    "attributes": {
                        "tnVzBrCPName": contract_name,
                        "status": "created,modified"
                    },
                    "children": []
                }
            }
            consumer_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{consumer_epg_dn}.json"

            response = requests.post(consumer_url, json=consumer_payload, headers=cisco_headers, verify=False)

            if response.status_code != 200:
                return Response(
                    {'status': 'error', 'message': f"Failed to map consumer EPG to contract"}
                )

            # Reverse provider payload
            reverse_provider_payload = {
                "fvRsProv": {
                    "attributes": {
                        "tnVzBrCPName": contract_name,
                        "status": "created,modified"
                    },
                    "children": []
                }
            }
            reverse_provider_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{consumer_epg_dn}.json"

            response = requests.post(reverse_provider_url, json=reverse_provider_payload, headers=cisco_headers,
                                     verify=False)

            if response.status_code == 200:

                # Reverse consumer payload
                reverse_consumer_payload = {
                    "fvRsCons": {
                        "attributes": {
                            "tnVzBrCPName": contract_name,
                            "status": "created,modified"
                        },
                        "children": []
                    }
                }
                reverse_consumer_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{provider_epg_dn}.json"

                response = requests.post(reverse_consumer_url, json=reverse_consumer_payload, headers=cisco_headers,
                                         verify=False)

                if response.status_code != 200:
                    return Response(
                        {'status': 'error', 'message': f"Failed to map provider EPG as consumer to consumer EPG"}
                    )
            else:
                return Response(
                    {'status': 'error', 'message': f"Failed to map consumer EPG as provider to provider EPG"})

        return Response({'status': 'success', 'message': f'EPGs mapped successfully in {directional} mode.'})

    @method_decorator(token_required)
    def delete(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        ap_name = request.data.get('ap_name')
        epg_name = request.data.get('epg_name')
        epg_dn = f"uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}"
        contract_name = request.data.get('contract_name')
        contract_dn = f"uni/tn-{base_tenant}/brc-{contract_name}"
        contract_type = request.data.get('contract_type')

        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        if not ap_name or not epg_name or not contract_name or not contract_type:
            return Response({'status': 'error', 'message': 'Missing Required Parameters'})

        # Verify if provider EPG exists under the specified AP
        if not verify_epg_exists(ap_name, epg_name, cisco_headers):
            return Response({'status': 'error', 'message': f'EPG "{epg_name}" not found in AP "{ap_name}".'})

        if not verify_contract_exists(base_tenant, contract_name, cisco_headers):
            return Response({'status': 'error', 'message': f'Contract does not exists'})

        relation_dn_for_payload = []
        if contract_type == 'Consumer':
            relation_dn = f"{epg_dn}/rscons-{contract_dn.split('/')[-1]}"
            relation_dn_for_payload = f"{epg_dn}/rscons-{contract_dn.split('/')[-1][4:]}"  # Remove 'brc-' prefix
        elif contract_type == 'Provider':
            relation_dn = f"{epg_dn}/rsprov-{contract_dn.split('/')[-1]}"
            relation_dn_for_payload = f"{epg_dn}/rsprov-{contract_dn.split('/')[-1][4:]}"  # Remove 'brc-' prefix

        delete_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/{relation_dn_for_payload}.json"

        payload = {
            "fvRsCons" if contract_type == "Consumer" else "fvRsProv": {
                "attributes": {
                    "dn": f"{relation_dn_for_payload}",
                    "status": "deleted"
                },
                "children": []
            }
        }

        response = requests.post(delete_url, headers=cisco_headers, json=payload, verify=False)

        if response.status_code == 200:
            return Response({'status': 'success', 'message': f"Contract removed successfully"})
        else:
            return Response({'status': 'error', 'message': f"Failed to remove contract from epg"})


############################################
############# SECURITY GROUP ###############
############################################

class SecurityGroup(APIView):
    @method_decorator(token_required)
    def get(self, request):
        user = request.user
        base_tenant = user.get('tenant_list')[0]

        token = request.user.get('openstack_token')
        security_group_list_data = security_group_list(token)

        return Response({"security_group_list_data": security_group_list_data}, status=status.HTTP_200_OK)

    @method_decorator(token_required)
    def post(self, request):
        user = request.user
        base_tenant = user.get('tenant_list')[0]

        token = request.user.get('openstack_token')
        sg_name = request.data.get('name')
        description = request.data.get('description')

        name = f"{base_tenant}-{sg_name}-sg"

        security_group_flag = any(security_group['name'] == name for security_group in security_group_list(token))

        if security_group_flag:
            messages = 'Security Group already exists with the same name'
            return Response({'status': 'error', 'message': messages})

        network_url = f"{NEUTRON_BASE_URL}/security-groups"
        headers = {"X-Auth-Token": token}
        payload = {
            "security_group": {
                "name": name,
                "description": description
            }
        }

        response = requests.post(network_url, json=payload, headers=headers, verify=False)
        if response.status_code == 201:
            return Response({'status': 'success', 'message': 'Security group created successfully'})
        else:
            return Response({'status': 'error', 'message': 'Failed to create security group'})

    @method_decorator(token_required)
    def delete(self, request):
        user = request.user
        base_tenant = user.get('tenant_list')[0]

        token = request.user.get('openstack_token')
        security_group_id = request.data.get('security_group_id')
        headers = {"X-Auth-Token": token}
        if not security_group_id:
            return Response({'status': 'error', 'message': 'Security Group ID is required'})

        delete_url = f"{NEUTRON_BASE_URL}/security-groups/{security_group_id}"
        response = requests.delete(delete_url, verify=False, headers=headers)
        if response.status_code == 204:
            return Response({'status': 'success', 'message': f'Security Group deleted successfully'})
        else:
            return Response({'status': 'error', 'message': f'Failed to delete security group'})


############################################
########### SECURITY GROUP RULE ############
############################################

class SecurityGroupRule(APIView):
    @method_decorator(token_required)
    def get(self, request, security_group_id):
        user = request.user
        base_tenant = user.get('tenant_list')[0]

        token = request.user.get('openstack_token')
        security_group_rules_data = security_group_rules_list(token, security_group_id)

        return Response({"security_group_rules_data": security_group_rules_data}, status=status.HTTP_200_OK)

    @method_decorator(token_required)
    def post(self, request, security_group_id):
        user = request.user
        base_tenant = user.get('tenant_list')[0]

        token = request.user.get('openstack_token')

        direction = request.data.get('direction')
        protocol = request.data.get('protocol')
        from_port = request.data.get('from_port')
        to_port = request.data.get('to_port')
        remote_type = request.data.get('remote_type')
        cidr = request.data.get('cidr')
        remote_security_group = request.data.get('remote_security_group')

        if not request.data:
            return Response({'status': 'error', 'message': 'Request body is empty.'})

        network_url = f"{NEUTRON_BASE_URL}/security-group-rules"
        headers = {"X-Auth-Token": token}

        # Construct data payload
        payload = {
            'security_group_rule': {
                'protocol': protocol,
                'security_group_id': security_group_id
            }
        }

        if protocol == "icmp":
            # Handle ICMP protocol
            payload['security_group_rule']['protocol'] = "icmp"
            payload['security_group_rule']['direction'] = direction
        elif protocol == "http":
            # Handle HTTP protocol
            payload['security_group_rule']['protocol'] = "tcp"
            payload['security_group_rule']['direction'] = "ingress"
            payload['security_group_rule']['port_range_min'] = 80
            payload['security_group_rule']['port_range_max'] = 80
        elif protocol == "https":
            # Handle HTTPS protocol
            payload['security_group_rule']['protocol'] = "tcp"
            payload['security_group_rule']['direction'] = "ingress"
            payload['security_group_rule']['port_range_min'] = 443
            payload['security_group_rule']['port_range_max'] = 443
        else:
            # Handle other protocols with port range and direction
            payload['security_group_rule']['protocol'] = protocol
            payload['security_group_rule']['direction'] = direction
            from_port = request.data.get('from_port')
            to_port = request.data.get('to_port')
            payload['security_group_rule']['port_range_min'] = from_port
            payload['security_group_rule']['port_range_max'] = to_port

        # Handle remote type (CIDR or Security Group)
        if remote_type == "cidr":
            payload['security_group_rule']['remote_ip_prefix'] = cidr
        else:
            payload['security_group_rule']['remote_group_id'] = remote_security_group

        response = requests.post(network_url, json=payload, headers=headers, verify=False)
        if response.status_code == 201:
            return Response({'status': 'success', 'message': 'Security group rule created successfully'})
        else:
            error_data = response.json().get('NeutronError')
            if error_data and error_data.get('type') == 'SecurityGroupRuleExists':
                error_message = f"Security group rule already exists. Rule id is {error_data.get('message')}"
            else:
                error_message = response.json().get('message', 'Failed to create security group rule')
            return Response({'status': 'error', 'message': error_message})

    @method_decorator(token_required)
    def delete(self, request, security_group_id):
        user = request.user
        base_tenant = user.get('tenant_list')[0]

        token = request.user.get('openstack_token')
        rule_id = request.data.get('rule_id')
        headers = {"X-Auth-Token": token}

        if not rule_id:
            return Response({'status': 'success', 'error': 'Rule ID is required'})

        delete_url = f"{NEUTRON_BASE_URL}/security-group-rules/{rule_id}"
        response = requests.delete(delete_url, verify=False, headers=headers)
        if response.status_code == 204:
            return Response({'status': 'success', 'message': f'Security Group Rule deleted successfully'})
        else:
            return Response({'status': 'error', 'message': f'Failed to delete security group rule'})


##################################################
############### COLO POLICY GROUP ################
##################################################

class ColoPolicyGroup(APIView):
    @method_decorator(token_required)
    def get(self, request):
        user = request.user
        cisco_token = get_cisco_token()
        base_tenant = user.get('tenant_list')[0]

        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        all_policy_groups = get_all_policy_groups(cisco_headers, base_tenant)
        leaf_access_policy_groups = all_policy_groups['leaf_access_policy_groups']
        vpc_policy_groups = all_policy_groups['vpc_policy_groups']

        return Response(
            {'leaf_access_policy_groups': leaf_access_policy_groups, 'vpc_policy_groups': vpc_policy_groups},
            status=status.HTTP_200_OK)

    @method_decorator(token_required)
    def post(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]

        profile_type = request.data.get('profile_type')
        policy_group_name = request.data.get('policy_group_name')
        port_channel_policy = request.data.get('port_channel_policy')

        if not request.data:
            return Response({'status': 'error', 'message': 'Request body is empty.'})

        if profile_type == 'Individual':
            if not all([profile_type, policy_group_name]):
                return Response({'status': 'error', 'message': 'Missing required parameters'})
        elif profile_type == 'Bond':
            if not all([profile_type, policy_group_name, port_channel_policy]):
                return Response({'status': 'error', 'message': 'Missing required parameters'})

        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        # Check the physical domain and access policies available in Cisco
        access_policies = get_access_policies(cisco_headers)
        aep_list = [i for i in access_policies if f'{base_tenant}-COLO-AEP' in i]

        if not aep_list:
            messages = 'No Physical domain or AEP policies are available'
            return Response({'status': 'error', 'message': messages})

        # Check if policy group already exists
        if profile_type == 'Individual':
            access_policy_group_name = f"PG_Access_{base_tenant}_{policy_group_name}"
            if policy_group_exists(cisco_headers, access_policy_group_name, 'Individual'):
                return Response({'status': 'error', 'message': 'Policy Group already exists with the same name'})
        elif profile_type == 'Bond':
            vpc_policy_group_name = f"PG_vPC_{base_tenant}_{policy_group_name}"
            if policy_group_exists(cisco_headers, vpc_policy_group_name, 'Bond'):
                return Response({'status': 'error', 'message': 'Policy Group already exists with the same name'})
        else:
            return Response({'status': 'error', 'message': 'Invalid profile type'}, status=400)

        # Create the policy group based on the profile type
        if profile_type == 'Individual':
            access_policy_group_name = f"PG_Access_{base_tenant}_{policy_group_name}"
            url = f'{CISCO_BASE_ROUTE_URL}/node/mo/uni/infra/funcprof/accportgrp-{access_policy_group_name}.json'

            payload = {
                "infraAccPortGrp": {
                    "attributes": {
                        "dn": f"uni/infra/funcprof/accportgrp-{access_policy_group_name}",
                        "name": access_policy_group_name,
                        "status": "created,modified"
                    },
                    "children": [
                        {
                            "infraRsAttEntP": {
                                "attributes": {
                                    "tDn": f"uni/infra/attentp-{aep_list[0]}",
                                    "status": "created,modified"
                                },
                                "children": []
                            }
                        }
                    ]
                }
            }
            response = requests.post(url, json=payload, headers=cisco_headers, verify=False)
        elif profile_type == "Bond":
            vpc_policy_group_name = f"PG_vPC_{base_tenant}_{policy_group_name}"

            url = f'{CISCO_BASE_ROUTE_URL}/node/mo/uni/infra/funcprof/accbundle-{vpc_policy_group_name}.json'

            payload = {
                "infraAccBndlGrp": {
                    "attributes": {
                        "dn": f"uni/infra/funcprof/accbundle-{vpc_policy_group_name}",
                        "lagT": "node",
                        "name": vpc_policy_group_name,
                        "rn": f"accbundle-{vpc_policy_group_name}",
                        "status": "created"
                    },
                    "children": [
                        {
                            "infraRsAttEntP": {
                                "attributes": {
                                    "tDn": f"uni/infra/attentp-{aep_list[0]}",
                                    "status": "created,modified"
                                },
                                "children": []
                            }
                        },
                        {
                            "infraRsLacpPol": {
                                "attributes": {
                                    "tnLacpLagPolName": port_channel_policy,
                                    "status": "created,modified"
                                },
                                "children": []
                            }
                        }
                    ]
                }
            }
            response = requests.post(url, json=payload, headers=cisco_headers, verify=False)
        else:
            return Response({'status': 'error', 'message': 'Invalid profile type'}, status=400)

        # Check the response
        if response.status_code == 200:
            return Response(
                {'status': 'success', 'message': f"Policy Group created successfully - {policy_group_name}"})
        else:
            return Response({'status': 'error', 'message': f"Failed to create Policy Group - {response.text}"})


class UpdateVpcPolicyGroup(APIView):
    @method_decorator(token_required)
    def post(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]

        vpc_policy_group = request.data.get('vpc_policy_group_name')
        port_channel_policy = request.data.get('port_channel_policy')

        if not vpc_policy_group or not port_channel_policy:
            return Response({
                'success': False,
                'message': 'Missing required fields: vpc_policy_group_name or port_channel_policy'
            }, status=status.HTTP_400_BAD_REQUEST)

        allowed_policies = ['Static', 'LACP_Active']

        if port_channel_policy not in allowed_policies:
            return Response({
                'success': False,
                'message': f"Invalid port_channel_policy '{port_channel_policy}'. Only 'Static' and 'LACP_Active' are allowed."
            }, status=status.HTTP_400_BAD_REQUEST)

        headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        vpc_data = {
            "infraRsLacpPol": {
                "attributes": {
                    "tnLacpLagPolName": port_channel_policy
                },
                "children": []
            }
        }

        vpc_url = f"https://172.31.231.91/api/node/mo/uni/infra/funcprof/accbundle-{vpc_policy_group}/rslacpPol.json"
        response = requests.post(vpc_url, json=vpc_data, headers=headers, verify=False)

        if response.status_code == 200:
            return Response({
                'success': True,
                'message': f"VPC Policy Group {vpc_policy_group} updated successfully"
            })
        else:
            return Response({
                'success': False,
                'message': f"Failed to update VPC Policy Group - {response.text}"
            }, status=response.status_code)


##################################################
############### COLO ACCESS PORT #################
##################################################

class ColoAccessPort(APIView):
    @method_decorator(token_required)
    def get(self, request, action=None, node_id=None, profile_name=None):
        user = request.user
        cisco_token = get_cisco_token()
        base_tenant = user.get('tenant_list')[0]
        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        # Fetch Node Details
        if request.path.startswith('/colo_access_port/fetch-node-details/') and node_id:
            try:
                node_details = get_node_details(cisco_headers, node_id, base_tenant)
                return Response({'success': True, 'data': node_details}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({'error': f'Unable to fetch details for node {node_id}'},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Fetch Interface Details
        elif request.path.startswith('/colo_access_port/fetch-interface-details/') and profile_name:
            profile = profile_name
            profile_name = f"{profile}-IntProf"

            # Handle compound profile names like "Node-201_Node-202_IntProf"
            profile_names = [profile_name]  # Start with the original profile name
            if '_' in profile_name:
                parts = profile_name.split('_')
                for part in parts:
                    if part.startswith('Node-'):
                        try:
                            node_number = int(part.replace('Node-', '').replace('-IntProf', ''))
                            node_profile = f"Node-{node_number}-IntProf"
                            profile_names.append(node_profile)
                        except ValueError:
                            print(f"Error extracting node number from: {part}")

            # Fetch interface details for all profile names
            all_interface_details = []
            for profile in profile_names:
                try:
                    interface_details = get_policy_groups(cisco_headers, profile, base_tenant)
                    all_interface_details.extend(interface_details)
                except Exception as e:
                    print(f"Error fetching policy group for profile {profile}: {e}")

            return Response({'success': True, 'data': all_interface_details}, status=status.HTTP_200_OK)

        else:
            try:
                all_node_ids, odd_node_ids = get_leaf_node_ids(cisco_headers)
                leaf_profiles = get_all_leaf_profiles(cisco_headers)

                return Response({
                    'node_details': all_node_ids,
                    'interface_details': leaf_profiles
                }, status=status.HTTP_200_OK)

            except Exception as e:
                return Response({'error': 'Unable to fetch data.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @method_decorator(token_required)
    def post(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        profile_type = request.data.get('profile_type')
        print(profile_type)

        if not request.data:
            return Response({'status': 'error', 'message': 'Request body is empty.'})

        if profile_type == 'Individual':
            leaf_access_policy_groups = request.data.get('leaf_access_policy_groups')
            leaf_profile = request.data.get('leaf_profile')

            leaf_profile_name_individual = ''
            details = ''

            if leaf_profile and leaf_profile.startswith('node-'):
                details = leaf_profile[len('node-'):]
                leaf_profile_name_individual = f"Node-{details}-IntProf"

            interface_id = request.data.get('interface_id')

            print(leaf_profile, leaf_access_policy_groups, interface_id)
            port_id = ''
            if interface_id and interface_id.startswith('eth1/'):
                port_id = interface_id[len('eth1/'):]

            profile_name = f"IntSel_1_{port_id}"

            url = f"https://172.31.231.91/api/node/mo/uni/infra/accportprof-{leaf_profile_name_individual}/hports-{profile_name}-typ-range.json"
            headers = {"Cookie": f"APIC-cookie={cisco_token}"}
            payload = {
                "infraHPortS": {
                    "attributes": {
                        "dn": f"uni/infra/accportprof-{leaf_profile_name_individual}/hports-{profile_name}-typ-range",
                        "name": profile_name,
                        "descr": base_tenant,
                        "rn": f"hports-{profile_name}-typ-range",
                        "status": "created,modified"
                    },
                    "children": [
                        {
                            "infraPortBlk": {
                                "attributes": {
                                    "dn": f"uni/infra/accportprof-{leaf_profile_name_individual}/hports-{profile_name}-typ-range/portblk-block3",
                                    "fromPort": port_id,
                                    "toPort": port_id,
                                    "name": "block3",
                                    "rn": "portblk-block3",
                                    "status": "created,modified"
                                },
                                "children": []
                            }
                        },
                        {
                            "infraRsAccBaseGrp": {
                                "attributes": {
                                    "tDn": f"uni/infra/funcprof/accportgrp-{leaf_access_policy_groups}",
                                    "status": "created,modified"
                                },
                                "children": []
                            }
                        }
                    ]
                }
            }

            # 1. Check if port already used in this profile
            check_url = f"https://172.31.231.91/api/node/mo/uni/infra/accportprof-{leaf_profile_name_individual}.json?query-target=children&target-subtree-class=infraHPortS"
            check_resp = requests.get(check_url, headers=headers, verify=False)

            if check_resp.status_code == 200:
                existing_entries = check_resp.json().get("imdata", [])
                for entry in existing_entries:
                    hports = entry.get("infraHPortS", {})
                    name = hports.get("attributes", {}).get("name", "")
                    if name.endswith(f"_{port_id}"):
                        return Response({
                            'success': False,
                            'message': f"Port eth1/{port_id} already exists in profile {leaf_profile_name_individual}. Overlapping not allowed."
                        }, status=status.HTTP_409_CONFLICT)

            response = requests.post(url, json=payload, headers=headers, verify=False)

            if response and response.status_code == 200:
                return Response({'success': True, 'message': "Individual Access Port created successfully"})
            else:
                return Response(
                    {'success': False, 'message': f"Failed to create Individual Access Port - {response.text}"})

        elif profile_type == 'Bond':
            vpc_policy_groups = request.data.get('vpc_policy_groups')
            leaf_profile1 = request.data.get('leaf_profile1')
            leaf_profile2 = request.data.get('leaf_profile2')

            cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

            if is_policy_group_already_used(cisco_headers, vpc_policy_groups):
                return Response({'success': False, 'message': f"Policy group '{vpc_policy_groups}' is already in use."})

            leaf_profile_name_bond = ''
            details1 = ''

            if leaf_profile1 and leaf_profile1.startswith('node-') and leaf_profile2 and leaf_profile2.startswith(
                    'node-'):
                details1 = leaf_profile1[len('node-'):]
                details2 = leaf_profile2[len('node-'):]
                leaf_profile_name_bond = f"Node-{details1}_Node-{details2}-IntProf"

            bond_interface_id = request.data.get('bond_interface_id')
            print(leaf_profile_name_bond, leaf_profile1, leaf_profile2, bond_interface_id)
            port_id = ''
            if bond_interface_id and bond_interface_id.startswith('eth1/'):
                port_id = bond_interface_id[len('eth1/'):]

            profile_name = f"IntSel_1_{port_id}"

            url = f"https://172.31.231.91/api/node/mo/uni/infra/accportprof-{leaf_profile_name_bond}/hports-{profile_name}-typ-range.json"
            headers = {"Cookie": f"APIC-cookie={cisco_token}"}
            payload = {
                "infraHPortS": {
                    "attributes": {
                        "dn": f"uni/infra/accportprof-{leaf_profile_name_bond}/hports-{profile_name}-typ-range",
                        "name": profile_name,
                        "descr": base_tenant,
                        "rn": f"hports-{profile_name}-typ-range",
                        "status": "created,modified"
                    },
                    "children": [
                        {
                            "infraPortBlk": {
                                "attributes": {
                                    "dn": f"uni/infra/accportprof-{leaf_profile_name_bond}/hports-{profile_name}-typ-range/portblk-block3",
                                    "fromPort": port_id,
                                    "toPort": port_id,
                                    "name": "block3",
                                    "rn": "portblk-block3",
                                    "status": "created,modified"
                                },
                                "children": []
                            }
                        },
                        {
                            "infraRsAccBaseGrp": {
                                "attributes": {
                                    "tDn": f"uni/infra/funcprof/accbundle-{vpc_policy_groups}",
                                    "status": "created,modified"
                                },
                                "children": []
                            }
                        }
                    ]
                }
            }

            check_url = f"https://172.31.231.91/api/node/mo/uni/infra/accportprof-{leaf_profile_name_bond}.json?query-target=children&target-subtree-class=infraHPortS"
            check_resp = requests.get(check_url, headers=headers, verify=False)

            if check_resp.status_code == 200:
                existing_entries = check_resp.json().get("imdata", [])
                for entry in existing_entries:
                    hports = entry.get("infraHPortS", {})
                    name = hports.get("attributes", {}).get("name", "")
                    if name.endswith(f"_{port_id}"):
                        return Response({
                            'success': False,
                            'message': f"Port eth1/{port_id} already exists in bonded profile {leaf_profile_name_bond}."
                        }, status=status.HTTP_409_CONFLICT)

            response = requests.post(url, json=payload, headers=headers, verify=False)
            if response and response.status_code == 200:
                return Response({'success': True, 'message': "Access Port created successfully"})
            else:
                return Response({'success': False, 'message': f"Failed to create Access Port - {response.text}"})

        else:
            return Response({'success': False, 'message': "Invalid profile type"}, status=status.HTTP_400_BAD_REQUEST)

    @method_decorator(token_required)
    def delete(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]

        profile = request.data.get('profile')
        interface_name = request.data.get('interface_name')

        if not profile or not interface_name:
            return Response({
                'success': False,
                'message': 'Missing required fields: profile or interface_name'
            }, status=status.HTTP_400_BAD_REQUEST)

        profile_name = f"{profile}-IntProf"

        headers = {
            "Cookie": f"APIC-cookie={cisco_token}",
            "Content-Type": "application/json"
        }

        delete_url = f"https://172.31.231.91/api/node/mo/uni/infra/accportprof-{profile_name}/hports-{interface_name}-typ-range.json"

        payload = {
            "infraHPortS": {
                "attributes": {
                    "dn": f"uni/infra/accportprof-{profile_name}/hports-{interface_name}-typ-range",
                    "status": "deleted"
                },
                "children": []
            }
        }

        try:
            delete_response = requests.delete(delete_url, headers=headers, json=payload, verify=False)

            if delete_response.status_code == 200:
                return Response({'success': True, 'message': f"Interface selector delete successfully."})
            else:
                return Response({
                    'success': False,
                    'message': f"Failed to delete interface selector. Status code: {delete_response.status_code}",
                    'details': delete_response.text
                }, status=delete_response.status_code)

        except Exception as e:
            return Response({
                'success': False,
                'message': f"Exception occurred while deleting interface: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


##################################################
############### COLO STATIC EPG ##################
##################################################

class ColoStaticEpgView(APIView):
    @method_decorator(token_required)
    def get(self, request, action=None, ap_name=None):
        user = request.user
        cisco_token = get_cisco_token()
        base_tenant = user.get('tenant_list')[0]
        cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        # Case 1: /deploy_static_epg/fetch-epgs/<ap_name>/
        if request.path.startswith('/deploy_static_epg/fetch-epgs/') and ap_name:
            try:
                epg_list = colo_epg_list(cisco_headers, ap_name, base_tenant)
                return Response({'success': True, 'data': epg_list}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({'success': False, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Case 2: /deploy_static_epg/fetch-epg-details/<ap_name>/
        elif request.path.startswith('/deploy_static_epg/fetch-epg-details/') and ap_name:
            epg_table_data = []
            try:
                epg_list_url = (
                    f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/ap-{ap_name}.json"
                    f"?query-target=subtree&target-subtree-class=fvAEPg"
                )
                epg_list_response = requests.get(epg_list_url, headers=cisco_headers, verify=False)
                if epg_list_response.status_code == 200:
                    epg_list_data = epg_list_response.json().get('imdata', [])
                    for epg_entry in epg_list_data:
                        epg_name = epg_entry.get('fvAEPg', {}).get('attributes', {}).get('name')
                        if epg_name:
                            epg_details_url = (
                                f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}.json"
                                f"?query-target=subtree&target-subtree-class=fvRsPathAtt"
                            )
                            epg_response = requests.get(epg_details_url, headers=cisco_headers, verify=False)
                            if epg_response.status_code == 200:
                                epg_data = epg_response.json().get('imdata', [])
                                found_path = False
                                for epg in epg_data:
                                    attr = epg['fvRsPathAtt']['attributes']
                                    dn = attr.get('dn')
                                    tDn = attr.get('tDn')
                                    encap = attr.get('encap')
                                    if dn and tDn:
                                        path = (
                                            tDn.replace("topology/", "")
                                            .replace("pathep-", "")
                                            .replace("paths-", "Node-")
                                            .replace("[", "")
                                            .replace("]", "")
                                            .replace("pod-", "Pod-")
                                        )
                                        epg_table_data.append({
                                            "ap_name": ap_name,
                                            "epg_name": epg_name,
                                            "modified_string": path,
                                            "encap": encap,
                                            "path": tDn
                                        })
                                        found_path = True
                                if not found_path:
                                    epg_table_data.append({
                                        "ap_name": ap_name,
                                        "epg_name": epg_name,
                                        "modified_string": "",
                                        "encap": "",
                                        "path": ""
                                    })
                return Response({'success': True, 'data': epg_table_data}, status=200)
            except Exception as e:
                return Response({'success': False, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Case 3: Default - return base metadata
        else:
            try:
                all_policy_groups = get_all_policy_groups(cisco_headers, base_tenant)
                all_node_ids = get_leaf_node_ids(cisco_headers)
                colo_ap_list = get_ap_list(cisco_headers, base_tenant)

                return Response({
                    'success': True,
                    'ap_list': colo_ap_list,
                    'all_node_list': all_node_ids,
                    'all_policy_groups': all_policy_groups
                }, status=status.HTTP_200_OK)

            except Exception:
                return Response({'success': False, 'message': 'Unable to fetch metadata.'}, status=500)

    @method_decorator(token_required)
    def post(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            profile_type = request.data.get('profile_type')
            cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}
            # 1. Individual Deployment
            if profile_type == "Individual":
                ap_name = request.data.get('ap_name_individual')
                epg_name = request.data.get('epg_name_individual')
                interface_id = request.data.get('interface_id')
                mode = request.data.get('mode_individual')
                leaf_profile = request.data.get('leaf_profile')
                node_id = leaf_profile.split('-')[-1]

                aep_name = get_aep_name_for_epg(cisco_headers, base_tenant, ap_name, epg_name)
                if not aep_name:
                    return Response({'success': False, 'message': 'Unable to determine AEP for the EPG'}, status=400)

                vlan_details = get_vlan_epg_details(cisco_headers, aep_name)
                vlan_encap = next((epg['encap'] for epg in vlan_details if epg['epg_name'] == epg_name), None)

                if not vlan_encap:
                    return Response({'success': False, 'message': 'VLAN for the EPG not found'}, status=400)

                payload = {
                    "fvRsPathAtt": {
                        "attributes": {
                            "dn": f"uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}/rspathAtt-[topology/pod-1/paths-{node_id}/pathep-[{interface_id}]]",
                            "encap": vlan_encap,
                            "mode": mode,
                            "tDn": f"topology/pod-1/paths-{node_id}/pathep-[{interface_id}]",
                            "rn": f"rspathAtt-[topology/pod-1/paths-{node_id}/pathep-[{interface_id}]]",
                            "status": "created"
                        },
                        "children": []
                    }
                }

                url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}/rspathAtt-[topology/pod-1/paths-{node_id}/pathep-[{interface_id}]].json"

                response = requests.post(url, json=payload, headers=cisco_headers, verify=False)

                if response.status_code == 200:
                    return Response({'success': True, 'message': "Deployed Port static EPG successfully"})
                else:
                    return Response(
                        {'success': False, 'message': f"Failed to deploy Port static EPG - {response.text}"},
                        status=500)

            # 2. Bond Deployment
            elif profile_type == "Bond":
                ap_name = request.data.get('ap_name_bond')
                epg_name = request.data.get('epg_name_bond')
                mode = request.data.get('mode_bond')
                vpc_group = request.data.get('vpc_policy_groups')
                node_id1 = request.data.get('leaf_profile1').split('-')[-1]
                node_id2 = request.data.get('leaf_profile2').split('-')[-1]
                node_bond = f"{node_id1}-{node_id2}"

                aep_name = get_aep_name_for_epg(cisco_headers, base_tenant, ap_name, epg_name)
                if not aep_name:
                    return Response({'success': False, 'message': 'Unable to determine AEP for the EPG'}, status=400)

                vlan_details = get_vlan_epg_details(cisco_headers, aep_name)
                vlan_encap = next((epg['encap'] for epg in vlan_details if epg['epg_name'] == epg_name), None)

                if not vlan_encap:
                    return Response({'success': False, 'message': 'VLAN for the EPG not found'}, status=400)

                payload = {
                    "fvRsPathAtt": {
                        "attributes": {
                            "dn": f"uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}/rspathAtt-[topology/pod-1/protpaths-{node_bond}/pathep-[{vpc_group}]]",
                            "encap": vlan_encap,
                            "mode": mode,
                            "tDn": f"topology/pod-1/protpaths-{node_bond}/pathep-[{vpc_group}]",
                            "rn": f"rspathAtt-[topology/pod-1/protpaths-{node_bond}/pathep-[{vpc_group}]]",
                            "status": "created"
                        },
                        "children": []
                    }
                }

                url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}/rspathAtt-[topology/pod-1/protpaths-{node_bond}/pathep-[{vpc_group}]].json"
                headers = {"Cookie": f"APIC-cookie={cisco_token}"}
                response = requests.post(url, json=payload, headers=cisco_headers, verify=False)

                if response.status_code == 200:
                    return Response({'success': True, 'message': "Deployed Bond static EPG successfully"})
                else:
                    return Response(
                        {'success': False, 'message': f"Failed to deploy Bond static EPG - {response.text}"},
                        status=500)

            # 4. Fallback
            return Response({'success': False, 'message': 'Invalid profile type or missing data'}, status=400)

        except Exception as e:
            return Response({'success': False, 'message': f'An error occurred: {str(e)}'}, status=500)

    @method_decorator(token_required)
    def delete(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]

        ap_name = request.data.get('ap_name')
        epg_name = request.data.get('epg_name')
        path = request.data.get('path')

        headers = {
            "Cookie": f"APIC-cookie={cisco_token}",
            "Content-Type": "application/json"
        }

        delete_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}/rspathAtt-[{path}].json"
        payload = {
            "fvRsPathAtt": {
                "attributes": {
                    "dn": f"uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}/rspathAtt-[{path}]",
                    "status": "deleted"
                },
                "children": []
            }
        }

        try:
            delete_response = requests.delete(delete_url, headers=headers, json=payload, verify=False)

            if delete_response.status_code == 200:
                return Response({'success': True, 'message': f"Static EPG removed successfully."})
            else:
                return Response({
                    'success': False,
                    'message': f"Failed to remove static epg. Status code: {delete_response.status_code}",
                    'details': delete_response.text
                }, status=delete_response.status_code)

        except Exception as e:
            return Response({
                'success': False,
                'message': f"Exception occurred while removing static epg: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


##################################################
################### L3 OUT #######################
##################################################


class L3OutView(APIView):
    @method_decorator(token_required)
    def get(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            cisco_headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            l3_out_data = l3_out_list(cisco_headers, base_tenant)
            vrf_data = get_vrf_list(cisco_headers, base_tenant)

            return Response({
                'vrf_list': vrf_data,
                'l3_out_data': l3_out_data,
            }, status=status.HTTP_200_OK)

        except Exception:
            return Response({'success': False, 'message': 'Unable to fetch metadata.'}, status=500)

    @method_decorator(token_required)
    def post(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            cisco_headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            profile_name = request.data.get('profile_name')
            subnet_ip = request.data.get('subnet_ip')
            vrf_name = request.data.get('vrf')
            l3_domain = f"{base_tenant}-L3Domain"

            l3out_name = f"{base_tenant}-{profile_name}-l3out"
            external_epg_name = f"{base_tenant}-{profile_name}-extepg"
            filter_name = f"{base_tenant}-{profile_name}-l3out-ext-flt"
            entry_name = f"{base_tenant}-{profile_name}-l3out-ext-entry"
            provider_contract_name = f"{base_tenant}-{profile_name}-l3out-ext-con-out"
            provider_subject_name = f"{base_tenant}-{profile_name}-l3out-ext-sub-out"
            consumer_contract_name = f"{base_tenant}-{profile_name}-l3out-ext-con-in"
            consumer_subject_name = f"{base_tenant}-{profile_name}-l3out-ext-sub-in"

            existing_l3_profiles = l3_out_list(cisco_headers, base_tenant)

            if any(profile["l3_out_name"] == l3out_name for profile in existing_l3_profiles) or \
                    filter_exists(filter_name, base_tenant, cisco_token) or \
                    contract_exists(provider_contract_name, base_tenant, cisco_token) or \
                    subject_exists(provider_subject_name, base_tenant, provider_contract_name, cisco_token):
                return Response({
                    'status': 'error',
                    'message': "L3 Out profile or its associated components already exists."
                })

            create_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}.json"
            payload = {
                "l3extOut": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}",
                        "name": l3out_name,
                        "rn": f"out-{l3out_name}",
                        "status": "created,modified"
                    },
                    "children": [
                        {
                            "l3extRsEctx": {
                                "attributes": {
                                    "tnFvCtxName": vrf_name,
                                    "status": "created,modified"
                                },
                                "children": []
                            }
                        },
                        {
                            "l3extRsL3DomAtt": {
                                "attributes": {
                                    "tDn": f"uni/l3dom-{l3_domain}",
                                    "status": "created,modified"
                                },
                                "children": []
                            }
                        }
                    ]
                }
            }

            response = requests.post(create_url, headers=cisco_headers, json=payload, verify=False)
            if response.status_code != 200:
                return Response({'status': 'error', 'error': response.text})

            external_epg_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/instP-{external_epg_name}.json"
            external_epg_payload = {
                "l3extInstP": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/instP-{external_epg_name}",
                        "name": external_epg_name,
                        "rn": f"instP-{external_epg_name}",
                        "status": "created"
                    },
                    "children": [
                        {
                            "l3extSubnet": {
                                "attributes": {
                                    "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/instP-{external_epg_name}/extsubnet-[{subnet_ip}]",
                                    "ip": subnet_ip,
                                    "scope": "import-security",
                                    "aggregate": "",
                                    "rn": f"extsubnet-[{subnet_ip}]",
                                    "status": "created"
                                },
                                "children": []
                            }
                        }
                    ]
                }
            }

            response = requests.post(external_epg_url, headers=cisco_headers, json=external_epg_payload, verify=False)
            if response.status_code != 200:
                return Response({'status': 'error', 'error': response.text})

            filter_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/flt-{filter_name}.json"
            filter_payload = {
                "vzFilter": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/flt-{filter_name}",
                        "name": filter_name,
                        "rn": f"flt-{filter_name}",
                        "status": "created,modified"
                    },
                    "children": [
                        {
                            "vzEntry": {
                                "attributes": {
                                    "dn": f"uni/tn-{base_tenant}/flt-{filter_name}/e-{entry_name}",
                                    "name": entry_name,
                                    "etherT": "ip",
                                    "prot": "tcp",
                                    "rn": f"e-{entry_name}",
                                    "status": "created,modified"
                                },
                                "children": []
                            }
                        }
                    ]
                }
            }

            response = requests.post(filter_url, headers=cisco_headers, json=filter_payload, verify=False)
            if response.status_code != 200:
                return Response({'status': 'error', 'error': response.text})

            # Provider contract creation
            provider_contract_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/brc-{provider_contract_name}.json"
            provider_contract_payload = {
                "vzBrCP": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/brc-{provider_contract_name}",
                        "name": provider_contract_name,
                        "rn": f"brc-{provider_contract_name}",
                        "status": "created"
                    },
                    "children": [
                        {
                            "vzSubj": {
                                "attributes": {
                                    "dn": f"uni/tn-{base_tenant}/brc-{provider_contract_name}/subj-{provider_subject_name}",
                                    "name": provider_subject_name,
                                    "rn": f"subj-{provider_subject_name}",
                                    "status": "created"
                                },
                                "children": [
                                    {
                                        "vzRsSubjFiltAtt": {
                                            "attributes": {
                                                "status": "created,modified",
                                                "tnVzFilterName": filter_name,
                                                "directives": ""
                                            },
                                            "children": []
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }

            response = requests.post(provider_contract_url, headers=cisco_headers, json=provider_contract_payload,
                                     verify=False)
            if response.status_code != 200:
                return Response({'status': 'error', 'error': response.text})

            # Consumer contract creation
            consumer_contract_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/brc-{consumer_contract_name}.json"
            consumer_contract_payload = {
                "vzBrCP": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/brc-{consumer_contract_name}",
                        "name": consumer_contract_name,
                        "rn": f"brc-{consumer_contract_name}",
                        "status": "created"
                    },
                    "children": [
                        {
                            "vzSubj": {
                                "attributes": {
                                    "dn": f"uni/tn-{base_tenant}/brc-{consumer_contract_name}/subj-{consumer_subject_name}",
                                    "name": consumer_subject_name,
                                    "rn": f"subj-{consumer_subject_name}",
                                    "status": "created"
                                },
                                "children": [
                                    {
                                        "vzRsSubjFiltAtt": {
                                            "attributes": {
                                                "status": "created,modified",
                                                "tnVzFilterName": filter_name,
                                                "directives": ""
                                            },
                                            "children": []
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }

            response = requests.post(consumer_contract_url, headers=cisco_headers, json=consumer_contract_payload,
                                     verify=False)
            if response.status_code != 200:
                return Response({'status': 'error', 'error': response.text})

            # Map contracts to external EPG
            for contract_type, contract_name in [("fvRsProv", provider_contract_name),
                                                 ("fvRsCons", consumer_contract_name)]:
                contract_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/instP-{external_epg_name}.json"
                contract_payload = {
                    contract_type: {
                        "attributes": {
                            "tnVzBrCPName": contract_name,
                            "status": "created,modified"
                        },
                        "children": []
                    }
                }
                response = requests.post(contract_url, headers=cisco_headers, json=contract_payload, verify=False)
                if response.status_code != 200:
                    return Response({'status': 'error', 'error': response.text})

            # Map contracts to VRF
            for contract_type, contract_name in [("vzRsAnyToCons", provider_contract_name),
                                                 ("vzRsAnyToProv", consumer_contract_name)]:
                vrf_mapping_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/ctx-{vrf_name}/any.json"
                vrf_mapping_payload = {
                    contract_type: {
                        "attributes": {
                            "tnVzBrCPName": contract_name,
                            "status": "created"
                        },
                        "children": []
                    }
                }
                response = requests.post(vrf_mapping_url, headers=cisco_headers, json=vrf_mapping_payload, verify=False)
                if response.status_code != 200:
                    return Response({'status': 'error', 'error': response.text})

            return Response({'status': 'success', 'message': f"L3 Out profile created successfully."})

        except Exception as e:
            return Response({'status': 'error', 'error': str(e)})

    @method_decorator(token_required)
    def delete(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            profile_name = request.data.get('profile_name')
            vrf_name = request.data.get('vrf_name')

            if not profile_name:
                return Response({'success': False, 'error': 'L3 Out Name is required'}, status=400)

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            delete_l3out_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{profile_name}.json"
            delete_l3out_payload = {
                "l3extOut": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/out-{profile_name}",
                        "status": "deleted"
                    },
                    "children": []
                }
            }

            delete_provider_contract_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/brc-{profile_name}-ext-con-out.json"
            delete_provider_contract_payload = {
                "vzBrCP": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/brc-{profile_name}-ext-con-out",
                        "status": "deleted"
                    },
                    "children": []
                }
            }

            delete_consumer_contract_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/brc-{profile_name}-ext-con-in.json"
            delete_consumer_contract_payload = {
                "vzBrCP": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/brc-{profile_name}-ext-con-in",
                        "status": "deleted"
                    },
                    "children": []
                }
            }

            delete_filter_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/flt-{profile_name}-ext-flt.json"
            delete_filter_payload = {
                "vzFilter": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/flt-{profile_name}-ext-flt",
                        "status": "deleted"
                    },
                    "children": []
                }
            }

            delete_provider_vrf_contract_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/ctx-{vrf_name}/any/rsanyToProv-{profile_name}-ext-con-in.json"
            delete_provider_vrf_contract_payload = {
                "vzRsAnyToProv": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/ctx-{vrf_name}/any/rsanyToProv-{profile_name}-ext-con-in",
                        "status": "deleted"
                    },
                    "children": []
                }
            }

            delete_consumer_vrf_contract_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/ctx-{vrf_name}/any/rsanyToCons-{profile_name}-ext-con-out.json"
            delete_consumer_vrf_contract_payload = {
                "vzRsAnyToCons": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/ctx-{vrf_name}/any/rsanyToCons-{profile_name}-ext-con-out",
                        "status": "deleted"
                    },
                    "children": []
                }
            }

            delete_l3out_response = requests.delete(delete_l3out_url, json=delete_l3out_payload, verify=False,
                                                    headers=headers)
            delete_provider_contract_response = requests.delete(delete_provider_contract_url,
                                                                json=delete_provider_contract_payload, verify=False,
                                                                headers=headers)
            delete_consumer_contract_response = requests.delete(delete_consumer_contract_url,
                                                                json=delete_consumer_contract_payload, verify=False,
                                                                headers=headers)
            delete_filter_response = requests.delete(delete_filter_url, json=delete_filter_payload, verify=False,
                                                     headers=headers)
            delete_provider_vrf_contract_response = requests.delete(delete_provider_vrf_contract_url,
                                                                    json=delete_provider_vrf_contract_payload,
                                                                    verify=False, headers=headers)
            delete_consumer_vrf_contract_response = requests.delete(delete_consumer_vrf_contract_url,
                                                                    json=delete_consumer_vrf_contract_payload,
                                                                    verify=False, headers=headers)

            if (
                    delete_l3out_response.status_code == 200 and
                    delete_provider_contract_response.status_code == 200 and
                    delete_consumer_contract_response.status_code == 200 and
                    delete_filter_response.status_code == 200 and
                    delete_provider_vrf_contract_response.status_code == 200 and
                    delete_consumer_vrf_contract_response.status_code == 200
            ):
                return Response({'status': 'success', 'message': f'L3Out Deleted Successfully'})
            else:
                return Response({
                    'status': 'error',
                    'message': 'Failed to delete one or more resources',
                    'details': {
                        'delete_l3out': delete_l3out_response.status_code,
                        'delete_provider_contract': delete_provider_contract_response.status_code,
                        'delete_consumer_contract': delete_consumer_contract_response.status_code,
                        'delete_filter': delete_filter_response.status_code,
                        'delete_provider_vrf_contract': delete_provider_vrf_contract_response.status_code,
                        'delete_consumer_vrf_contract': delete_consumer_vrf_contract_response.status_code,
                    }
                }, status=500)

        except Exception as e:
            return Response({'status': 'error', 'message': str(e)}, status=500)


class ExtSubnetView(APIView):
    @method_decorator(token_required)
    def get(self, request, l3out_name):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}"
            }

            # Get external EPG name
            ext_epg_url = (
                f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}.json"
                f"?query-target=children&target-subtree-class=l3extInstP"
            )

            response = requests.get(ext_epg_url, headers=headers, verify=False)
            ext_epg_name = None

            if response.status_code == 200:
                data = response.json().get("imdata", [])
                for item in data:
                    if 'l3extInstP' in item and 'attributes' in item['l3extInstP']:
                        ext_epg_name = item['l3extInstP']['attributes'].get('name')
                        break

            # Get external subnets
            ext_subnet = []
            if ext_epg_name:
                ext_subnet_url = (
                    f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/"
                    f"instP-{ext_epg_name}.json"
                    f"?query-target=subtree&target-subtree-class=l3extSubnet"
                    f"&rsp-subtree-class=l3extRsSubnetToProfile,l3extRsSubnetToRtSumm"
                )
                response = requests.get(ext_subnet_url, headers=headers, verify=False)

                if response.status_code == 200:
                    ext_subnet_json = response.json().get("imdata", [])
                    for route in ext_subnet_json:
                        subnet = route.get("l3extSubnet", {}).get("attributes", {})
                        ext_subnet.append({
                            "ip": subnet.get("ip"),
                            "descr": subnet.get("descr"),
                            "scope": subnet.get("scope"),
                        })
                else:
                    return Response({
                        "success": False,
                        "message": "Failed to fetch external subnet data",
                        "status_code": response.status_code
                    }, status=502)

            return Response({
                "l3out_name": l3out_name,
                "ext_epg_name": ext_epg_name,
                "ext_subnet": ext_subnet
            })

        except Exception as e:
            return Response({"success": False, "message": str(e)}, status=500)

    @method_decorator(token_required)
    def post(self, request):
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]

        l3out_name = request.data.get('l3out_name')
        ext_epg_name = request.data.get('extepg_name')
        subnet_ip = request.data.get('subnet_ip')

        headers = {
            "Cookie": f"APIC-cookie={cisco_token}",
            "Content-Type": "application/json"
        }

        # Check if subnet already exists
        ext_subnet_url = (
            f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/"
            f"instP-{ext_epg_name}.json"
            f"?query-target=subtree&target-subtree-class=l3extSubnet"
            f"&rsp-subtree-class=l3extRsSubnetToProfile,l3extRsSubnetToRtSumm"
        )

        response = requests.get(ext_subnet_url, headers=headers, verify=False)

        if response.status_code == 200:
            ext_subnet_json = response.json().get("imdata", [])
            for route in ext_subnet_json:
                subnet = route.get("l3extSubnet", {}).get("attributes", {})
                if subnet.get("ip") == subnet_ip:
                    return Response({'status': 'error', 'message': 'External Subnet already exists'}, status=409)

        # Create new subnet
        create_ext_subnet_url = (
            f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/"
            f"instP-{ext_epg_name}/extsubnet-[{subnet_ip}].json"
        )
        create_ext_subnet_payload = {
            "l3extSubnet": {
                "attributes": {
                    "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/instP-{ext_epg_name}/extsubnet-[{subnet_ip}]",
                    "ip": subnet_ip,
                    "scope": "import-security,",
                    "aggregate": "",
                    "rn": f"extsubnet-[{subnet_ip}]",
                    "status": "created"
                },
                "children": []
            }
        }

        response = requests.post(create_ext_subnet_url, headers=headers, json=create_ext_subnet_payload, verify=False)

        if response.status_code == 200:
            return Response({'status': 'success', 'message': 'External Subnet created successfully'})
        else:
            return Response({
                'status': 'error',
                'message': f"Failed to create External Subnet: {response.status_code} {response.text}"
            }, status=response.status_code)

    @method_decorator(token_required)
    def delete(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            l3out_name = request.data.get('l3out_name')
            ext_epg_name = request.data.get('extepg_name')
            subnet_ip = request.data.get('subnet_ip')

            if not ext_epg_name or not l3out_name or not subnet_ip:
                return Response({'success': False, 'error': 'Missing Parameters'}, status=status.HTTP_400_BAD_REQUEST)

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            delete_ext_subnet_url = (
                f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/"
                f"instP-{ext_epg_name}/extsubnet-[{subnet_ip}].json"
            )
            delete_ext_subnet_payload = {
                "l3extSubnet": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/instP-{ext_epg_name}/extsubnet-[{subnet_ip}]",
                        "status": "deleted"
                    },
                    "children": []
                }
            }

            response = requests.delete(delete_ext_subnet_url, json=delete_ext_subnet_payload, verify=False,
                                       headers=headers)

            if response.status_code == 200:
                return Response({'status': 'success', 'message': 'External Subnet deleted successfully'},
                                status=status.HTTP_200_OK)
            else:
                return Response(
                    {'status': 'error', 'message': f"Failed to delete External Subnet: {response.status_code}"},
                    status=response.status_code)

        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


##################################################
################# NODE PROFILE ###################
##################################################

class NodeProfileView(APIView):
    @method_decorator(token_required)
    def get(self, request, l3out_name=None):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            cisco_headers = {
                "Cookie": f"APIC-cookie={cisco_token}"
            }

            selected_node_profile = request.GET.get('node_profile')  # optional for detail

            node_profiles = []
            node_data = []

            if not l3out_name:
                return Response({'success': False, 'error': 'L3Out name is required in URL'}, status=400)

            if selected_node_profile:
                # fetch_node_profile_details
                api_url = (
                    f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{selected_node_profile}.json"
                    "?query-target=subtree&target-subtree-class=l3extRsNodeL3OutAtt,l3extLoopBackIfP,mplsNodeSidP"
                )
                response = requests.get(api_url, headers=cisco_headers, verify=False)

                if response.status_code == 200:
                    data = response.json().get('imdata', [])
                    for item in data:
                        attrs = item.get('l3extRsNodeL3OutAtt', {}).get('attributes', {})
                        rtr_id = attrs.get('rtrId')
                        tDn = attrs.get('tDn')
                        node_dn = attrs.get('dn')
                        loopback = attrs.get('rtrIdLoopBack')
                        rtr_id_loopback = loopback

                        loopback_found = False
                        for lp in data:
                            lp_attrs = lp.get('l3extLoopBackIfP', {}).get('attributes', {})
                            dn = lp_attrs.get('dn')
                            if dn:
                                lp_dn = dn.split('/lbp-')[0] if '/lbp-' in dn else dn
                                if node_dn == lp_dn:
                                    rtr_id_loopback = lp_attrs.get('addr')
                                    loopback_found = True
                                    break

                        if not loopback_found and rtr_id_loopback == "yes":
                            rtr_id_loopback = rtr_id

                        if rtr_id and tDn and rtr_id_loopback:
                            node_data.append({
                                'rtrId': rtr_id,
                                'tDn': tDn,
                                'loopback': loopback,
                                'rtrIdLoopBack': rtr_id_loopback
                            })

            node_profiles = get_node_profiles(cisco_headers, l3out_name, base_tenant)

            return Response({
                'node_profiles': node_profiles,
                'node_data': node_data,
            })

        except KeyError:
            return Response({'success': False, 'error': 'Session expired'}, status=403)

    @method_decorator(token_required)
    def post(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            node_profile_type = request.data.get('node_profile_type')
            l3out_name = request.data.get('l3out_name')
            node_id = request.data.get('leaf_profile', '').lower()
            router_ip = request.data.get('router_ip')
            loopback_ip = request.data.get('loopback_ip')
            use_router_ip_as_loopback = request.data.get('use_router_ip_as_loopback')

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            if node_profile_type == "New":
                node = request.data.get('node_profile_name')
                node_name = f"{base_tenant}-{node}-nodeProfile" if node else None

                if not l3out_name or not node_name:
                    return Response({
                        'status': 'error',
                        'message': "Profile name or node name is missing. Please ensure all required fields are filled."
                    }, status=status.HTTP_400_BAD_REQUEST)

                create_node_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_name}.json"

                rtrIdLoopBack = "true" if use_router_ip_as_loopback else "false"
                if use_router_ip_as_loopback:
                    loopback_ip = router_ip

                node_payload = {
                    "l3extLNodeP": {
                        "attributes": {
                            "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_name}",
                            "name": node_name,
                            "rn": f"lnodep-{node_name}",
                            "status": "created"
                        },
                        "children": [
                            {
                                "l3extRsNodeL3OutAtt": {
                                    "attributes": {
                                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_name}/rsnodeL3OutAtt-[topology/pod-1/{node_id}]",
                                        "tDn": f"topology/pod-1/{node_id}",
                                        "rtrId": router_ip,
                                        "rtrIdLoopBack": rtrIdLoopBack,
                                        "rn": f"rsnodeL3OutAtt-[topology/pod-1/{node_id}]",
                                        "status": "created"
                                    },
                                    "children": []
                                }
                            }
                        ]
                    }
                }

                if loopback_ip:
                    node_payload["l3extLNodeP"]["children"][0]["l3extRsNodeL3OutAtt"]["children"].append({
                        "l3extLoopBackIfP": {
                            "attributes": {
                                "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_name}/rsnodeL3OutAtt-[topology/pod-1/{node_id}]/lbp-[{loopback_ip}]",
                                "addr": loopback_ip,
                                "rn": f"lbp-[{loopback_ip}]",
                                "status": "created"
                            },
                            "children": []
                        }
                    })

                response = requests.post(create_node_url, json=node_payload, headers=headers, verify=False)

                if response.status_code == 200:
                    return Response({'status': 'success', 'message': "Node Profile created successfully."})
                else:
                    return Response({
                        'status': 'error',
                        'message': f"Failed to create Node Profile. Response: {response.text}"
                    }, status=response.status_code)

            elif node_profile_type == "Existing":
                node_name = request.data.get('node_profile')

                create_node_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_name}/rsnodeL3OutAtt-[topology/pod-1/{node_id}].json"

                rtrIdLoopBack = "true" if use_router_ip_as_loopback else "false"
                if use_router_ip_as_loopback:
                    loopback_ip = router_ip

                node_payload = {
                    "l3extRsNodeL3OutAtt": {
                        "attributes": {
                            "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_name}/rsnodeL3OutAtt-[topology/pod-1/{node_id}]",
                            "tDn": f"topology/pod-1/{node_id}",
                            "rtrId": router_ip,
                            "rtrIdLoopBack": rtrIdLoopBack,
                            "rn": f"rsnodeL3OutAtt-[topology/pod-1/{node_id}]",
                            "status": "created"
                        },
                        "children": []
                    }
                }

                if loopback_ip:
                    node_payload["l3extRsNodeL3OutAtt"]["children"].append({
                        "l3extLoopBackIfP": {
                            "attributes": {
                                "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_name}/rsnodeL3OutAtt-[topology/pod-1/{node_id}]/lbp-[{loopback_ip}]",
                                "addr": loopback_ip,
                                "rn": f"lbp-[{loopback_ip}]",
                                "status": "created"
                            },
                            "children": []
                        }
                    })

                response = requests.post(create_node_url, json=node_payload, headers=headers, verify=False)

                if response.status_code == 200:
                    return Response({'status': 'success', 'message': "Node Profile created successfully."})
                else:
                    return Response({
                        'status': 'error',
                        'message': f"Failed to create Node Profile. Response: {response.text}"
                    }, status=response.status_code)

        except Exception as e:
            return Response({'status': 'error', 'message': str(e)}, status=500)

        return Response({'status': 'error', 'message': 'Invalid request method'}, status=405)

    @method_decorator(token_required)
    def delete(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            l3out_name = request.data.get('l3out_name')
            node_profile = request.data.get('node_profile')

            if not node_profile or not l3out_name:
                return Response({'success': False, 'error': 'Missing Parameters'}, status=status.HTTP_400_BAD_REQUEST)

            url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}.json"
            payload = {
                "l3extLNodeP": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}",
                        "status": "deleted"
                    },
                    "children": []
                }
            }

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            response = requests.delete(url, json=payload, headers=headers, verify=False)

            if response.status_code == 200:
                return Response({'success': True, 'message': 'Node Profile deleted successfully'})
            else:
                return Response({
                    'success': False,
                    'error': f'Failed to delete Node Profile: {response.status_code}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ConfiguredNodeView(APIView):
    @method_decorator(token_required)
    def post(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            update_type = request.data.get('ip_type')
            l3out_name = request.data.get('l3out_name')
            node_profile = request.data.get('node_profile')
            tDn = request.data.get('tdn')

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            if update_type == "Router ID":
                router_ip = request.data.get('router_ip')

                update_node_url = (
                    f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}"
                    f"/lnodep-{node_profile}/rsnodeL3OutAtt-[{tDn}].json"
                )

                node_payload = {
                    "l3extRsNodeL3OutAtt": {
                        "attributes": {
                            "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/rsnodeL3OutAtt-[{tDn}]",
                            "rtrId": router_ip
                        },
                        "children": []
                    }
                }

                update_node_response = requests.post(update_node_url, json=node_payload, headers=headers, verify=False)

                if update_node_response.status_code == 200:
                    return Response({'status': 'success', 'message': "Router ID updated successfully."})
                else:
                    return Response({
                        'status': 'error',
                        'message': f"Failed to update Node Profile. Response: {update_node_response.text}"
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            else:
                loopback_ip = request.data.get('loopback_ip')

                update_loopback_url = (
                    f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}"
                    f"/rsnodeL3OutAtt-[{tDn}]/lbp-[{loopback_ip}].json"
                )

                loopback_payload = {
                    "l3extLoopBackIfP": {
                        "attributes": {
                            "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/rsnodeL3OutAtt-[{tDn}]/lbp-[{loopback_ip}]",
                            "addr": loopback_ip,
                            "status": "created",
                            "rn": f"lbp-[{loopback_ip}]"
                        },
                        "children": []
                    }
                }

                update_loopback_response = requests.post(update_loopback_url, json=loopback_payload, headers=headers,
                                                         verify=False)

                if update_loopback_response.status_code == 200:
                    return Response({'status': 'success', 'message': "Loopback Address updated successfully."})
                else:
                    return Response({
                        'status': 'error',
                        'message': f"Failed to update Node Profile. Response: {update_loopback_response.text}"
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @method_decorator(token_required)
    def delete(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            l3out_name = request.data.get('l3out_name')
            node_profile = request.data.get('node_profile')
            tDn = request.data.get('tdn')

            if not node_profile or not l3out_name or not tDn:
                return Response({'success': False, 'error': 'Missing Parameters'}, status=status.HTTP_400_BAD_REQUEST)

            url = (
                f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}"
                f"/lnodep-{node_profile}/rsnodeL3OutAtt-[{tDn}].json"
            )
            payload = {
                "l3extRsNodeL3OutAtt": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/rsnodeL3OutAtt-[{tDn}]",
                        "status": "deleted"
                    },
                    "children": []
                }
            }

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            response = requests.delete(url, json=payload, headers=headers, verify=False)

            if response.status_code == 200:
                return Response({'success': True, 'message': 'Removed configured node from node profile successfully'})
            else:
                return Response({
                    'success': False,
                    'error': f'Failed to remove configured node: {response.status_code}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class StaticRouteView(APIView):
    @method_decorator(token_required)
    def get(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            l3out_name = request.GET.get("l3out_name")
            node_profile = request.GET.get("node_profile")
            tDn = request.GET.get("tdn")

            if not l3out_name or not node_profile or not tDn:
                return Response({'success': False, 'error': 'Missing parameters'}, status=400)

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}"
            }

            static_route_url = (
                f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/"
                f"lnodep-{node_profile}/rsnodeL3OutAtt-[{tDn}].json"
                f"?query-target=subtree&target-subtree-class=ipRouteP&rsp-subtree=children"
            )

            response = requests.get(static_route_url, headers=headers, verify=False)
            static_route = []

            if response.status_code == 200:
                static_route_json = response.json().get("imdata", [])
                for route in static_route_json:
                    ip_route = route.get("ipRouteP", {}).get("attributes", {})
                    children = route.get("ipRouteP", {}).get("children", [])
                    next_hops = []

                    for child in children:
                        nexthop = child.get("ipNexthopP", {}).get("attributes", {})
                        if nexthop:
                            next_hops.append({
                                "nhAddr": nexthop.get("nhAddr"),
                                "pref": nexthop.get("pref"),
                            })

                    static_route.append({
                        "ip": ip_route.get("ip"),
                        "descr": ip_route.get("descr"),
                        "pref": ip_route.get("pref"),
                        "next_hops": next_hops,
                    })
            else:
                return Response({'success': False, 'error': 'Failed to fetch static route'},
                                status=response.status_code)

            return Response({
                "static_route": static_route
            })

        except KeyError:
            return Response({'success': False, 'error': 'Session expired'}, status=403)
        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=500)

    @method_decorator(token_required)
    def post(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            l3out_name = request.data.get('l3out_name')
            node_profile = request.data.get('node_profile')
            path = request.data.get('path')
            prefix_ip = request.data.get('prefix_ip')
            nexthop_ip = request.data.get('nexthop_ip')
            preference = request.data.get('preference')
            route_control = request.data.get('bfd')

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            # Check if route already exists
            static_route_url = (
                f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/"
                f"lnodep-{node_profile}/rsnodeL3OutAtt-[{path}].json"
                f"?query-target=subtree&target-subtree-class=ipRouteP&rsp-subtree=children"
            )

            response = requests.get(static_route_url, headers=headers, verify=False)

            if response.status_code == 200:
                static_route_json = response.json().get("imdata", [])
                for route in static_route_json:
                    ip_route = route.get("ipRouteP", {}).get("attributes", {})
                    if ip_route.get("ip") == prefix_ip:
                        return Response({'status': 'error', 'message': 'Static route already exists'}, status=409)

            # Create static route
            create_url = (
                f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/"
                f"lnodep-{node_profile}/rsnodeL3OutAtt-[{path}]/rt-[{prefix_ip}].json"
            )

            payload = {
                "ipRouteP": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/rsnodeL3OutAtt-[{path}]/rt-[{prefix_ip}]",
                        "ip": prefix_ip,
                        **({"rtCtrl": "bfd"} if route_control == "on" else {}),
                        "rn": f"rt-[{prefix_ip}]",
                        "status": "created"
                    },
                    "children": [
                        {
                            "ipNexthopP": {
                                "attributes": {
                                    "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/rsnodeL3OutAtt-[{path}]/rt-[{prefix_ip}]/nh-[{nexthop_ip}]",
                                    "nhAddr": nexthop_ip,
                                    "pref": preference,
                                    "rn": f"nh-[{nexthop_ip}]",
                                    "status": "created"
                                },
                                "children": []
                            }
                        }
                    ]
                }
            }

            response = requests.post(create_url, headers=headers, json=payload, verify=False)

            if response.status_code == 200:
                return Response({'status': 'success', 'message': 'Static Route created successfully'})
            else:
                return Response(
                    {'status': 'error',
                     'message': f"Failed to create Static Route: {response.status_code} {response.text}"},
                    status=response.status_code
                )

        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=500)

    @method_decorator(token_required)
    def delete(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            l3out_name = request.data.get('l3out_name')
            node_profile = request.data.get('node_profile')
            path = request.data.get('path')
            ip = request.data.get('ip')

            if not all([l3out_name, node_profile, path, ip]):
                return Response({'success': False, 'error': 'Missing Parameters'}, status=status.HTTP_400_BAD_REQUEST)

            delete_url = (
                f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/"
                f"lnodep-{node_profile}/rsnodeL3OutAtt-[{path}]/rt-[{ip}].json"
            )

            payload = {
                "ipRouteP": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/rsnodeL3OutAtt-[{path}]/rt-[{ip}]",
                        "status": "deleted"
                    },
                    "children": []
                }
            }

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            response = requests.delete(delete_url, json=payload, headers=headers, verify=False)

            if response.status_code == 200:
                return Response({'status': 'success', 'message': 'Static Route deleted successfully'})
            else:
                return Response({
                    'status': 'error',
                    'message': f"Failed to delete Static Route: {response.status_code}"
                }, status=response.status_code)

        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


##################################################
############## INTERFACE PROFILE #################
##################################################

class InterfaceProfileView(APIView):
    @method_decorator(token_required)
    def get(self, request, l3out_name=None):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]
            cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

            selected_node_profile = request.GET.get('node_profile')
            selected_interface_profile = request.GET.get('interface_profile')

            if not l3out_name:
                return Response({'success': False, 'error': 'L3Out name is required in URL'}, status=400)

            # Case 1: Only node_profile → Return interface profiles
            if selected_node_profile and not selected_interface_profile:
                interface_profiles = get_interface_profiles(cisco_headers, l3out_name, base_tenant,
                                                            selected_node_profile)
                return Response({
                    'l3out_name': l3out_name,
                    'node_profile': selected_node_profile,
                    'interface_profiles': interface_profiles,
                    'interface_profile_data': []
                })

            # Case 2: node_profile + interface_profile → Return detailed interface config
            elif selected_node_profile and selected_interface_profile:
                api_url = (
                    f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/"
                    f"lnodep-{selected_node_profile}/lifp-{selected_interface_profile}.json"
                    "?query-target=subtree&target-subtree-class=l3extRsPathL3OutAtt,l3extIp,ptpRtdEpgCfg"
                )
                response = requests.get(api_url, headers=cisco_headers, verify=False)

                interface_profile_data = []
                if response.status_code == 200:
                    data = response.json().get('imdata', [])
                    for item in data:
                        attributes = item.get('l3extRsPathL3OutAtt', {}).get('attributes', {})
                        if attributes.get('ifInstT') == 'l3-port':
                            interface_profile_data.append({
                                'tDn': attributes.get('tDn'),
                                'addr': attributes.get('addr'),
                                'mtu': attributes.get('mtu')
                            })

                return Response({
                    'l3out_name': l3out_name,
                    'node_profile': selected_node_profile,
                    'interface_profile': selected_interface_profile,
                    'interface_profile_data': interface_profile_data
                })

            # Case 3: Missing node_profile
            else:
                return Response({'success': False, 'error': 'Missing node_profile or interface_profile'}, status=400)

        except KeyError:
            return Response({'success': False, 'error': 'Session expired'}, status=403)

    @method_decorator(token_required)
    def post(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            l3out_name = request.data.get('l3out_name')
            node_name = request.data.get('node_profile')

            node_id = request.data.get('leaf_profile', '').lower()
            interface_id = request.data.get('interface_id')
            mtu = request.data.get('mtu')
            interface_ip = request.data.get('interface_ip')

            interface_profile_type = request.data.get('interface_profile_type')

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            if interface_profile_type == "New":
                interface = request.data.get('interface_profile_name')
                interface_name = f"{base_tenant}-{interface}-interfaceProfile" if interface else None

                if not l3out_name or not interface_name:
                    return Response({
                        'status': 'error',
                        'message': "Profile name or node name is missing. Please ensure all required fields are filled."
                    }, status=status.HTTP_400_BAD_REQUEST)

                create_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_name}/lifp-{interface_name}.json"

                payload = {
                    "l3extLIfP": {
                        "attributes": {
                            "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_name}/lifp-{interface_name}",
                            "name": interface_name,
                            "rn": f"lifp-{interface_name}",
                            "status": "created"
                        },
                        "children": [
                            {
                                "l3extRsPathL3OutAtt": {
                                    "attributes": {
                                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_name}/lifp-{interface_name}/rspathL3OutAtt-[topology/pod-1/paths-{node_id.split('-')[-1]}/pathep-[{interface_id}]]",
                                        "mac": "00:22:BD:F8:19:FF",
                                        "ifInstT": "l3-port",
                                        "addr": interface_ip,
                                        "mtu": mtu,
                                        "tDn": f"topology/pod-1/paths-{node_id.split('-')[-1]}/pathep-[{interface_id}]",
                                        "rn": f"rspathL3OutAtt-[topology/pod-1/paths-{node_id.split('-')[-1]}/pathep-[{interface_id}]]",
                                        "status": "created"
                                    },
                                    "children": []
                                }
                            }
                        ]
                    }
                }

                resp = requests.post(create_url, json=payload, headers=headers, verify=False)

                if resp.status_code == 200:
                    return Response({'status': 'success', 'message': "Routed Interface Profile created successfully."})
                else:
                    return Response({
                        'status': 'error',
                        'message': f"Failed to create Routed Interface Profile. Response: {resp.text}"
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            elif interface_profile_type == "Existing":
                interface_name = request.data.get('interface_profile')

                create_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_name}/lifp-{interface_name}.json"

                payload = {
                    "l3extRsPathL3OutAtt": {
                        "attributes": {
                            "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_name}/lifp-{interface_name}/rspathL3OutAtt-[topology/pod-1/paths-{node_id.split('-')[-1]}/pathep-[{interface_id}]]",
                            "mac": "00:22:BD:F8:19:FF",
                            "ifInstT": "l3-port",
                            "addr": interface_ip,
                            "mtu": mtu,
                            "tDn": f"topology/pod-1/paths-{node_id.split('-')[-1]}/pathep-[{interface_id}]",
                            "rn": f"rspathL3OutAtt-[topology/pod-1/paths-{node_id.split('-')[-1]}/pathep-[{interface_id}]]",
                            "status": "created"
                        },
                        "children": []
                    }
                }

                resp = requests.post(create_url, json=payload, headers=headers, verify=False)

                if resp.status_code == 200:
                    return Response({'status': 'success', 'message': "Routed Interface Profile created successfully."})
                else:
                    return Response({
                        'status': 'error',
                        'message': f"Failed to create Routed Interface Profile. Response: {resp.text}"
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'status': 'error', 'message': 'Invalid request method'},
                        status=status.HTTP_405_METHOD_NOT_ALLOWED)

    @method_decorator(token_required)
    def delete(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            l3out_name = request.data.get('l3out_name')
            node_profile = request.data.get('node_profile')
            interface_profile = request.data.get('interface_profile')

            if not l3out_name or not node_profile or not interface_profile:
                return Response({'success': False, 'error': 'Missing Parameters'}, status=status.HTTP_400_BAD_REQUEST)

            delete_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}.json"
            payload = {
                "l3extLIfP": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}",
                        "status": "deleted"
                    },
                    "children": []
                }
            }
            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            response = requests.delete(delete_url, json=payload, headers=headers, verify=False)

            if response.status_code == 200:
                return Response({'success': True, 'message': 'Interface Profile deleted successfully'})
            else:
                return Response(
                    {'success': False, 'error': f'Failed to delete interface profile: {response.status_code}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RoutedInterfaceView(APIView):
    @method_decorator(token_required)
    def post(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            l3out_name = request.data.get('l3out_name')
            node_profile = request.data.get('node_profile')
            interface_profile = request.data.get('interface_profile')
            tDn = request.data.get('path')
            addr = request.data.get('address')
            mtu = request.data.get('mtu')

            if not all([node_profile, l3out_name, interface_profile, tDn, addr, mtu]):
                return Response({'success': False, 'error': 'Missing Parameters'}, status=status.HTTP_400_BAD_REQUEST)

            update_url = (
                f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/"
                f"lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[{tDn}].json"
            )

            payload = {
                "l3extRsPathL3OutAtt": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[{tDn}]",
                        "addr": addr,
                        "mtu": mtu
                    },
                    "children": []
                }
            }

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            response = requests.post(update_url, json=payload, headers=headers, verify=False)

            if response.status_code == 200:
                return Response({'success': True, 'message': 'Routed Interface Profile updated successfully'})
            else:
                return Response({
                    'success': False,
                    'error': f'Failed to update Routed Interface Profile: {response.status_code}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @method_decorator(token_required)
    def delete(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            l3out_name = request.data.get('l3out_name')
            node_profile = request.data.get('node_profile')
            interface_profile = request.data.get('interface_profile')
            tDn = request.data.get('path')

            if not node_profile or not l3out_name or not interface_profile or not tDn:
                return Response({'success': False, 'error': 'Missing Parameters'}, status=status.HTTP_400_BAD_REQUEST)

            delete_routed_interface_url = (
                f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/"
                f"out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[{tDn}].json"
            )

            payload = {
                "l3extRsPathL3OutAtt": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[{tDn}]",
                        "status": "deleted"
                    },
                    "children": []
                }
            }

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            response = requests.delete(delete_routed_interface_url, json=payload, headers=headers, verify=False)

            if response.status_code == 200:
                return Response({'success': True, 'message': 'Routed Interface removed successfully'})
            else:
                return Response(
                    {'success': False, 'error': f'Failed to remove Routed Interface: {response.status_code}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SviInterfaceProfileAPIView(APIView):
    @method_decorator(token_required)
    def get(self, request, l3out_name=None):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]
            cisco_headers = {"Cookie": f"APIC-cookie={cisco_token}"}

            vpc = get_fabric_path_eps(cisco_headers,base_tenant)

            # Case: Only /svi_interface_profile – return vpc
            if not l3out_name:
                return Response({'vpc': vpc})

            selected_node_profile = request.GET.get('node_profile')
            selected_interface_profile = request.GET.get('interface_profile')

            # Case 1: Only node_profile → Return interface profiles
            if selected_node_profile and not selected_interface_profile:
                interface_profiles = get_interface_profiles(cisco_headers, l3out_name, base_tenant, selected_node_profile)
                return Response({
                    'l3out_name': l3out_name,
                    'node_profile': selected_node_profile,
                    'interface_profiles': interface_profiles,
                    'interface_profile_data': []
                })

            # Case 2: node_profile + interface_profile → Return detailed interface config
            elif selected_node_profile and selected_interface_profile:
                api_url = (
                    f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/"
                    f"lnodep-{selected_node_profile}/lifp-{selected_interface_profile}.json"
                    "?query-target=subtree&target-subtree-class=l3extRsPathL3OutAtt,l3extIp,l3extMember"
                )

                response = requests.get(api_url, headers=cisco_headers, verify=False)
                interface_profile_data = []

                if response.status_code == 200:
                    data = response.json().get('imdata', [])
                    for item in data:
                        attributes = item.get('l3extRsPathL3OutAtt', {}).get('attributes', {})
                        if_inst_type = attributes.get('ifInstT')

                        if if_inst_type == "l3-port":
                            continue

                        if if_inst_type == "ext-svi":
                            node_dn = attributes.get('dn')
                            result = node_dn.split('rspathL3OutAtt-')[-1].strip("[]")
                            addr = attributes.get('addr')
                            mtu = attributes.get('mtu')
                            encap = attributes.get('encap')
                            mode = "Trunk" if attributes.get('mode') == 'regular' else "Access(untagged)"

                            addr_A = addr_B = side_A = side_B = sec_addr = ""
                            for member in data:
                                if 'l3extIp' in member:
                                    l3ext_ip_dn = member['l3extIp']['attributes'].get('dn', '')
                                    if node_dn in l3ext_ip_dn:
                                        sec_addr = member['l3extIp']['attributes'].get('addr')

                                member_attributes = member.get('l3extMember', {}).get('attributes', {})
                                side = member_attributes.get('side')
                                dn = member_attributes.get('dn', '')

                                if side == 'A' and node_dn == dn.split('/mem-A')[0]:
                                    addr_A = member_attributes.get('addr')
                                    side_A = side
                                elif side == 'B' and node_dn == dn.split('/mem-B')[0]:
                                    addr_B = member_attributes.get('addr')
                                    side_B = side

                            interface_profile_data.append({
                                "result": result,
                                "addr": addr,
                                "mtu": mtu,
                                "encap": encap,
                                "addr_A": addr_A,
                                "side_A": side_A,
                                "addr_B": addr_B,
                                "side_B": side_B,
                                "sec_addr": sec_addr,
                                "mode": mode,
                            })

                return Response({
                    'l3out_name': l3out_name,
                    'node_profile': selected_node_profile,
                    'interface_profile': selected_interface_profile,
                    'interface_profile_data': interface_profile_data,
                })

            # Case 3: Missing node_profile
            return Response({'success': False, 'error': 'Missing node_profile or interface_profile'}, status=400)

        except KeyError:
            return Response({'success': False, 'error': 'Session expired'}, status=403)

    @method_decorator(token_required)
    def delete(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            l3out_name = request.data.get('l3out_name')
            node_profile = request.data.get('node_profile')
            interface_profile = request.data.get('interface_profile')

            if not l3out_name or not node_profile or not interface_profile:
                return Response({'success': False, 'error': 'Missing Parameters'}, status=status.HTTP_400_BAD_REQUEST)

            delete_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}.json"
            payload = {
                "l3extLIfP": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}",
                        "status": "deleted"
                    },
                    "children": []
                }
            }
            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            response = requests.delete(delete_url, json=payload, headers=headers, verify=False)

            if response.status_code == 200:
                return Response({'success': True, 'message': 'Interface Profile deleted successfully'})
            else:
                return Response(
                    {'success': False, 'error': f'Failed to delete interface profile: {response.status_code}'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @method_decorator(token_required)
    def post(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            data = request.data
            l3out_name = data.get('l3out_name')
            node_profile = data.get('node_profile')
            profile_type = data.get('profile_type')
            interface_profile_type = data.get('interface_profile_type')
            mtu = data.get('mtu')
            vlan = data.get('vlan_id')
            vlan_id = f"vlan-{vlan}"
            mode_bond = data.get('mode_bond')

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            is_valid_vlan = l3out_vlan_pool_check(vlan_id, base_tenant, headers)
            if is_valid_vlan is False:
                return Response({'status': 'error', 'message': "VLAN is not within range"})

            if profile_type == "Individual":
                node_id = data.get('leaf_profile').split('-')[-1]
                interface_id = data.get('interface_id')
                addr = data.get('addr')

                if interface_profile_type == "New":
                    interface = data.get('interface_profile_name')
                    interface_name = f"{base_tenant}-{interface}-interfaceProfile" if interface else None

                    if not l3out_name or not interface_name:
                        return Response({'status': 'error', 'message': "Profile name or node name is missing."})

                    url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_name}.json"
                    payload = {
                        "l3extLIfP": {
                            "attributes": {
                                "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_name}",
                                "name": interface_name,
                                "rn": f"lifp-{interface_name}",
                                "status": "created"
                            },
                            "children": [{
                                "l3extRsPathL3OutAtt": {
                                    "attributes": {
                                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_name}/rspathL3OutAtt-[topology/pod-1/paths-{node_id}/pathep-[{interface_id}]]",
                                        "mac": "00:22:BD:F8:19:FF",
                                        "ifInstT": "ext-svi",
                                        "encap": vlan_id,
                                        "addr": addr,
                                        "mtu": mtu,
                                        "mode": mode_bond,
                                        "tDn": f"topology/pod-1/paths-{node_id}/pathep-[{interface_id}]",
                                        "rn": f"rspathL3OutAtt-[topology/pod-1/paths-{node_id}/pathep-[{interface_id}]]",
                                        "status": "created"
                                    },
                                    "children": []
                                }
                            }]
                        }
                    }
                    res = requests.post(url, json=payload, headers=headers, verify=False)
                    if res.status_code == 200:
                        return Response(
                            {'status': 'success', 'message': "SVI Interface Profile created successfully."})
                    return Response({'status': 'error',
                                     'message': f"Failed to create SVI Interface Profile. Response: {res.text}"})

                elif interface_profile_type == "Existing":
                    interface_profile = data.get('interface_profile')
                    url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[topology/pod-1/paths-{node_id}/pathep-[{interface_id}]].json"
                    payload = {
                        "l3extRsPathL3OutAtt": {
                            "attributes": {
                                "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[topology/pod-1/paths-{node_id}/pathep-[{interface_id}]]",
                                "mac": "00:22:BD:F8:19:FF",
                                "ifInstT": "ext-svi",
                                "encap": vlan_id,
                                "addr": addr,
                                "mtu": mtu,
                                "mode": mode_bond,
                                "tDn": f"topology/pod-1/paths-{node_id}/pathep-[{interface_id}]",
                                "rn": f"rspathL3OutAtt-[topology/pod-1/paths-{node_id}/pathep-[{interface_id}]]",
                                "status": "created"
                            },
                            "children": []
                        }
                    }
                    res = requests.post(url, json=payload, headers=headers, verify=False)
                    if res.status_code == 200:
                        return Response(
                            {'status': 'success', 'message': "SVI Interface Profile created successfully."})
                    return Response({'status': 'error',
                                     'message': f"Failed to create SVI Interface Profile. Response: {res.text}"})

            elif profile_type == "Bond":
                vpc_policy_groups = data.get('vpc_policy_groups')
                side_a = data.get('side_a')
                side_b = data.get('side_b')
                sec_addr = data.get('sec_addr')

                if interface_profile_type == "New":
                    interface = data.get('interface_profile_name')
                    interface_name = f"{base_tenant}-{interface}-interfaceProfile" if interface else None
                    if not l3out_name or not interface_name:
                        return Response({'status': 'error', 'message': "Profile name or node name is missing."})

                    url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_name}.json"
                    payload = self._build_bond_payload(base_tenant, l3out_name, node_profile, interface_name,
                                                       vpc_policy_groups, mtu, vlan_id, mode_bond, side_a, side_b,
                                                       sec_addr)
                    res = requests.post(url, json=payload, headers=headers, verify=False)
                    if res.status_code == 200:
                        return Response(
                            {'status': 'success', 'message': "SVI Interface Profile created successfully."})
                    return Response({'status': 'error',
                                     'message': f"Failed to create SVI Interface Profile. Response: {res.text}"})

                elif interface_profile_type == "Existing":
                    interface_profile = data.get('interface_profile')
                    url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[topology/{vpc_policy_groups}].json"
                    payload = self._build_bond_payload(base_tenant, l3out_name, node_profile, interface_profile,
                                                       vpc_policy_groups, mtu, vlan_id, mode_bond, side_a, side_b,
                                                       sec_addr)
                    res = requests.post(url, json=payload, headers=headers, verify=False)
                    if res.status_code == 200:
                        return Response(
                            {'status': 'success', 'message': "SVI Interface Profile created successfully."})
                    return Response({'status': 'error',
                                     'message': f"Failed to create SVI Interface Profile. Response: {res.text}"})

        except Exception as e:
            return Response({'status': 'error', 'message': str(e)})

        return Response({'status': 'error', 'message': 'Invalid request method'})

    def _build_bond_payload(self, tenant, l3out, node_profile, interface_name, vpc_pg, mtu, vlan_id, mode_bond,
                            side_a, side_b, sec_addr):
        return {
            "l3extRsPathL3OutAtt": {
                "attributes": {
                    "dn": f"uni/tn-{tenant}/out-{l3out}/lnodep-{node_profile}/lifp-{interface_name}/rspathL3OutAtt-[topology/{vpc_pg}]",
                    "mac": "00:22:BD:F8:19:FF",
                    "ifInstT": "ext-svi",
                    "mtu": mtu,
                    "encap": vlan_id,
                    "mode": mode_bond,
                    "tDn": f"topology/{vpc_pg}",
                    "rn": f"rspathL3OutAtt-[topology/{vpc_pg}]",
                    "status": "created"
                },
                "children": [
                    {
                        "l3extMember": {
                            "attributes": {
                                "dn": f"uni/tn-{tenant}/out-{l3out}/lnodep-{node_profile}/lifp-{interface_name}/rspathL3OutAtt-[topology/{vpc_pg}]/mem-A",
                                "addr": side_a,
                                "llAddr": "0.0.0.0",
                                "rn": "mem-A",
                                "status": "created"
                            },
                            "children": [{
                                "l3extIp": {
                                    "attributes": {
                                        "dn": f"uni/tn-{tenant}/out-{l3out}/lnodep-{node_profile}/lifp-{interface_name}/rspathL3OutAtt-[topology/{vpc_pg}]/mem-A/addr-[{sec_addr}]",
                                        "addr": sec_addr,
                                        "rn": f"addr-[{sec_addr}]",
                                        "status": "created"
                                    },
                                    "children": []
                                }
                            }]
                        }
                    },
                    {
                        "l3extMember": {
                            "attributes": {
                                "dn": f"uni/tn-{tenant}/out-{l3out}/lnodep-{node_profile}/lifp-{interface_name}/rspathL3OutAtt-[topology/{vpc_pg}]/mem-B",
                                "side": "B",
                                "addr": side_b,
                                "llAddr": "0.0.0.0",
                                "rn": "mem-B",
                                "status": "created"
                            },
                            "children": [{
                                "l3extIp": {
                                    "attributes": {
                                        "dn": f"uni/tn-{tenant}/out-{l3out}/lnodep-{node_profile}/lifp-{interface_name}/rspathL3OutAtt-[topology/{vpc_pg}]/mem-B/addr-[{sec_addr}]",
                                        "addr": sec_addr,
                                        "rn": f"addr-[{sec_addr}]",
                                        "status": "created"
                                    },
                                    "children": []
                                }
                            }]
                        }
                    }
                ]
            }
        }


class SviRoutedInterfaceAPIView(APIView):
    @method_decorator(token_required)
    def delete(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            l3out_name = request.data.get('l3out_name')
            node_profile = request.data.get('node_profile')
            interface_profile = request.data.get('interface_profile')
            tDn = request.data.get('path')

            if not node_profile or not l3out_name or not interface_profile or not tDn:
                return Response({'success': False, 'error': 'Missing Parameters'}, status=400)

            delete_url = (
                f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/"
                f"lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[{tDn}].json"
            )

            delete_payload = {
                "l3extRsPathL3OutAtt": {
                    "attributes": {
                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[{tDn}]",
                        "status": "deleted"
                    },
                    "children": []
                }
            }

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            response = requests.delete(delete_url, json=delete_payload, headers=headers, verify=False)

            if response.status_code == 200:
                return Response({'success': True, 'message': 'SVI Interface removed successfully'})
            else:
                return Response({'success': False, 'error': f'Failed to remove svi interface: {response.status_code}'}, status=response.status_code)

        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=500)

    @method_decorator(token_required)
    def post(self, request):
        try:
            cisco_token = get_cisco_token()
            user = request.user
            base_tenant = user.get('tenant_list')[0]

            l3out_name = request.data.get('l3out_name')
            node_profile = request.data.get('node_profile')
            interface_profile = request.data.get('interface_profile')
            tDn = request.data.get('path')
            addr_a = request.data.get('addr_a')
            addr_b = request.data.get('addr_b')
            addr = request.data.get('address')
            mtu = request.data.get('mtu')
            vlan = request.data.get('encap')
            vlan_id = f"vlan-{vlan}"
            mode_bond = request.data.get('mode')

            if mode_bond == "Trunk":
                mode_bond = "regular"
            elif mode_bond == "Access":
                mode_bond = "untagged"

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}",
                "Content-Type": "application/json"
            }

            is_valid_vlan = l3out_vlan_pool_check(vlan_id, base_tenant, headers)
            if not is_valid_vlan:
                return Response({'success': False, 'error': "VLAN is not within range"}, status=400)

            if 'eth1/' in tDn:
                if not all([node_profile, l3out_name, interface_profile, tDn, addr, mtu, vlan_id, mode_bond]):
                    return Response({'success': False, 'error': 'Missing Parameters'}, status=400)

                update_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[{tDn}].json"
                payload = {
                    "l3extRsPathL3OutAtt": {
                        "attributes": {
                            "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[{tDn}]",
                            "encap": vlan_id,
                            "addr": addr,
                            "mode": mode_bond,
                            "mtu": mtu
                        },
                        "children": []
                    }
                }

                response = requests.post(update_url, json=payload, headers=headers, verify=False)

                if response.status_code == 200:
                    return Response({'success': True, 'message': 'SVI Interface Profile updated successfully'})
                else:
                    return Response({'success': False, 'error': f'Failed to update SVI Interface Profile: {response.status_code} {response.text}'}, status=response.status_code)
            else:
                if not all([node_profile, l3out_name, interface_profile, tDn, addr_a, addr_b, mtu, vlan_id, mode_bond]):
                    return Response({'success': False, 'error': 'Missing Parameters'}, status=400)

                update_url = f"https://172.31.231.91/api/node/mo/uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[{tDn}].json"
                payload = {
                    "l3extRsPathL3OutAtt": {
                        "attributes": {
                            "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[{tDn}]",
                            "encap": vlan_id,
                            "addr": addr,
                            "mode": mode_bond,
                            "mtu": mtu
                        },
                        "children": [
                            {
                                "l3extMember": {
                                    "attributes": {
                                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[{tDn}]/mem-A",
                                        "addr": addr_a
                                    },
                                    "children": []
                                }
                            },
                            {
                                "l3extMember": {
                                    "attributes": {
                                        "dn": f"uni/tn-{base_tenant}/out-{l3out_name}/lnodep-{node_profile}/lifp-{interface_profile}/rspathL3OutAtt-[{tDn}]/mem-B",
                                        "addr": addr_b
                                    },
                                    "children": []
                                }
                            }
                        ]
                    }
                }

                print(payload)

                response = requests.post(update_url, json=payload, headers=headers, verify=False)

                if response.status_code == 200:
                    return Response({'success': True, 'message': 'SVI Interface Profile updated successfully'})
                else:
                    return Response({'success': False, 'error': f'Failed to update SVI Interface Profile: {response.text}'}, status=response.status_code)

        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=500)

