from .config import CISCO_PASS, CISCO_USER, CISCO_AUTH_URL
from .config import KEYSTONE_URL, CISCO_BASE_ROUTE_URL, CISCO_REFRESH_URL, NEUTRON_BASE_URL
import requests

def security_group_list(token):
    network_url = f"{NEUTRON_BASE_URL}/security-groups"
    headers = {"X-Auth-Token": token}
    response = requests.get(network_url, verify=False, headers=headers)
    security_group_data = response.json().get("security_groups")

    security_group_list = []
    for security_group in security_group_data:
        data = {
            'id': security_group.get("id"),
            'name': security_group.get('name'),
            'description': security_group.get('description'),
        }
        security_group_list.append(data)

    return security_group_list


def security_group_rules_list(token, security_group_id):
    network_url = f"{NEUTRON_BASE_URL}/security-group-rules?security_group_id={security_group_id}"
    headers = {"X-Auth-Token": token}
    response = requests.get(network_url, verify=False, headers=headers)
    security_group_rules_data = response.json().get("security_group_rules")

    security_group_rules_list = []
    for rule in security_group_rules_data:
        data = {
            'id': rule.get("id"),
            'security_group_id': rule.get('security_group_id'),
            'direction': rule.get('direction'),
            'protocol': rule.get('protocol'),
            'ethertype': rule.get('ethertype'),
            'port_range_min': rule.get('port_range_min'),
            'port_range_max': rule.get('port_range_max'),
            'remote_ip_prefix': rule.get('remote_ip_prefix'),
            'remote_group_id': rule.get('remote_group_id'),
        }
        security_group_rules_list.append(data)

    return security_group_rules_list

