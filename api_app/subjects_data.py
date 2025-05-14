from .config import CISCO_PASS, CISCO_USER, CISCO_AUTH_URL
from .config import KEYSTONE_URL, CISCO_BASE_ROUTE_URL, CISCO_REFRESH_URL, NEUTRON_BASE_URL

import requests

def list_filters(contract_name, subject_name, cisco_token, base_tenant):
    cisco_headers = {'Cookie': f"APIC-cookie={cisco_token}"}
    filters_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}/brc-{contract_name}/subj-{subject_name}.json?query-target=children&target-subtree-class=vzRsSubjFiltAtt,vzInTerm,vzOutTerm"
    response = requests.get(filters_url, headers=cisco_headers, verify=False)

    filter_list = []
    if response.status_code == 200:
        filters_json = response.json().get("imdata", [])
        for filter in filters_json:
            filter_ctx = filter.get("vzRsSubjFiltAtt", {}).get("attributes", {})
            filter_name = filter_ctx.get("tnVzFilterName")
            dn = filter_ctx.get("dn")
            tenant = ""
            if dn:
                dn_parts = dn.split("/")
                if len(dn_parts) > 1:
                    tenant = dn_parts[1].replace("tn-", "")  # Remove "tn-" prefix
            action = filter_ctx.get("action")
            priorityOverride = filter_ctx.get("priorityOverride")
            directives = filter_ctx.get("directives")
            state = filter_ctx.get("state")
            filter_list.append({
                "filter_name": filter_name,
                "tenant": tenant,
                "action": action,
                "priorityOverride": priorityOverride,
                "directives": directives,
                "state": state
            })

    return filter_list
