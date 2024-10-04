# myapp/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .utils import user_login, token_required, get_cisco_token, get_openstack_token
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from .zone_data import vrf_list, ap_list
from .network_data import network_list, subnet_list
import requests

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
        return Response({'message': 'Please Provide Username,Domain and Passsword Details'}, status=status.HTTP_400_BAD_REQUEST)


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
        vrf_zone_name = f"{base_tenant}-{zone_name}-vrf"
        ap_zone_name = f"{base_tenant}-{zone_name}-ap"

        headers = {"Cookie": f"APIC-cookie={cisco_token}"}

        vrf_data = vrf_list(cisco_token, base_tenant)
        ap_data = ap_list(cisco_token, base_tenant)
        if vrf_zone_name in [i.get('name') for i in vrf_data] or ap_zone_name in [i.get('name') for i in ap_data]:
            messages = 'Zone already exists with same name'
            return Response({'status': 'error',  "message": messages})

        # Create VRF
        vrf_payload = {
            "fvCtx": {
                "attributes": {
                    "name": vrf_zone_name
                }
            }
        }
        vrf_creation_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}.json"
        vrf_response = requests.post(vrf_creation_url, headers=headers, json=vrf_payload, verify=False)

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
            ap_response = requests.post(ap_creation_url, headers=headers, json=ap_payload, verify=False)

            if ap_response.status_code == 200:
                messages = f"Zone created successfully - {vrf_zone_name}"
                return Response({'status': 'success',  "message": messages})
            else:
                # Rollback Zone creation if AP creation fails
                rollback_vrf_url = f"https://172.31.1.12/api/node/mo/uni/tn-{base_tenant}/ctx-{vrf_zone_name}.json"
                requests.delete(rollback_vrf_url, headers=headers, verify=False)
                messages = f"Failed to create Zone"
                return Response({'status': 'error',  "message": messages})
        else:
            messages = f"Failed to create Zone"
            return Response({'status': 'error', "message": messages})


class Network(APIView):
    @method_decorator(token_required)
    def get(self, request, token):
        openstack_token = ""
        cisco_token = get_cisco_token()
        user = request.user
        base_tenant = user.get('tenant_list')[0]
        network_data = network_list(openstack_token, base_tenant, cisco_token)
        subnet_data = subnet_list(openstack_token)
        return Response({'network_data': network_data, 'subnet_data': subnet_data}, status=status.HTTP_200_OK)





