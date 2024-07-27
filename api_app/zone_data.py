from .config import CISCO_BASE_ROUTE_URL
import requests

def vrf_list(cisco_token, base_tenant):
    vrf_url = f"{CISCO_BASE_ROUTE_URL}node/mo/uni/tn-{base_tenant}.json?query-target=children&target-subtree-class=fvCtx"
    vrf_data = []
    # Add authentication cookie to headers
    headers = {
        "Cookie": f"APIC-cookie={cisco_token}"
    }
    # Retrieve VRF data
    vrf_response = requests.get(vrf_url, headers=headers, verify=False)

    # Check VRF data response
    if vrf_response.status_code == 200:
        vrf_data_json = vrf_response.json().get("imdata", [])
        # Preprocess VRF data
        for vrf in vrf_data_json:
            vrf_ctx = vrf.get("fvCtx", {}).get("attributes", {})
            name = vrf_ctx.get("name")
            dn = vrf_ctx.get("dn")
            tenant, bridge_domain = "", ""
            if dn:
                dn_parts = dn.split("/")
                if len(dn_parts) > 1:
                    tenant = dn_parts[1].replace("tn-", "")  # Remove "tn-" prefix
                if len(dn_parts) > 3:
                    bridge_domain = dn_parts[3]
            seg = vrf_ctx.get("seg")
            pcTag = vrf_ctx.get("pcTag")
            pcEnfPref = vrf_ctx.get("pcEnfPref")
            pcEnfDir = vrf_ctx.get("pcEnfDir")
            vrf_data.append({
                "name": name,
                "tenant": tenant,
                "bridge_domain": bridge_domain,
                "seg": seg,
                "pcTag": pcTag,
                "pcEnfPref": pcEnfPref,
                "pcEnfDir": pcEnfDir
            })
        return vrf_data

def ap_list(cisco_token, base_tenant):
    ap_url = f"{CISCO_BASE_ROUTE_URL}/node/mo/uni/tn-{base_tenant}.json?query-target=children&target-subtree-class=fvAp"
    ap_data = []

    headers = {
        "Cookie": f"APIC-cookie={cisco_token}"
    }

    # Retrieve AP data
    ap_response = requests.get(ap_url, headers=headers, verify=False)

    # Check AP data response
    if ap_response.status_code == 200:
        ap_data_json = ap_response.json().get("imdata", [])

        for ap in ap_data_json:
            ap_ctx = ap.get("fvAp", {}).get("attributes", {})
            name = ap_ctx.get("name")
            prio = ap_ctx.get("prio")

            ap_data.append({
                "name": name,
                "prio": prio
            })
        return ap_data
