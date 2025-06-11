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
        vrf_creation_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}.json"
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
            ap_creation_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}.json"
            ap_response = requests.post(ap_creation_url, headers=cisco_headers, json=ap_payload, verify=False)

            if ap_response.status_code == 200:
                messages = f"Zone created successfully - {vrf_zone_name}"
                return Response({'status': 'success', "message": messages})
            else:
                # Rollback Zone creation if AP creation fails
                rollback_vrf_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}/ctx-{vrf_zone_name}.json"
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
            delete_bd_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}/BD-{bd_name}.json"
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
            delete_epg_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}.json"
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
            delete_vlan_url = f"https://172.31.1.12/api/node/mo/uni/infra/attentp-development_AEP_HPServers/gen-default/rsfuncToEpg-[uni/tn-{base_tenant}/ap-{ap_name}/epg-{epg_name}].json"
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
        contract_creation_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}/brc-{contract_name}.json"
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
            subject_creation_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}/brc-{contract_name}/subj-{subject_name}.json"
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
                subject_filter_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}/brc-{contract_name}/subj-{subject_name}.json"
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

        update_subject_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}/brc-{contract_name}/subj-{subject_name}.json"

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

        delete_subject_filter_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}/brc-{contract_name}/subj-{subject_name}/rssubjFiltAtt-{filter_name}.json"
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
        filter_creation_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}/flt-{filter_name}.json"

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

        delete_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}/flt-{filter_name}.json"
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
        entry_creation_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}/flt-{filter_name}.json"

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

        delete_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}/flt-{filter_name}/e-{entry_id}.json"
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

        return Response({'leaf_access_policy_groups': leaf_access_policy_groups, 'vpc_policy_groups': vpc_policy_groups}, status=status.HTTP_200_OK)


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
                return Response({'error': f'Unable to fetch details for node {node_id}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
                            node_number = int(part[len('Node-'):])
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


