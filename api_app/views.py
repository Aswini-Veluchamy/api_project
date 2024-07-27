from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
import requests
from .serializers import ZoneSerializer
from .get_token import get_cisco_token, get_openstack_token, get_vrf_list, get_ap_list

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

class TestView(APIView):
    def get(self, request):
        return Response({'message': 'Authenticated successfully!'}, status=status.HTTP_200_OK)


import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .authentication import OpenStackAuthentication
from .serializers import ZoneSerializer, GetZoneSerializer

class GetZoneDataView(APIView):
    authentication_classes = [OpenStackAuthentication]

    def get(self, request):
        cisco_token = get_cisco_token()  # Replace with actual token retrieval logic
        base_tenant = 'development'  # Replace with actual tenant retrieval logic

        headers = {
            "Cookie": f"APIC-cookie={cisco_token}"
        }

        vrf_url = f"https://172.31.1.11/api/node/class/fvCtx.json"
        ap_url = f"https://172.31.1.11/api/node/class/fvAp.json"

        try:
            vrf_response = requests.get(vrf_url, headers=headers, verify=False)
            ap_response = requests.get(ap_url, headers=headers, verify=False)

            if vrf_response.status_code == 200 and ap_response.status_code == 200:
                vrf_data = vrf_response.json().get('imdata', [])
                ap_data = ap_response.json().get('imdata', [])

                zones = []
                for vrf in vrf_data:
                    vrf_name = vrf.get('fvCtx', {}).get('attributes', {}).get('name')
                    if base_tenant in vrf_name:
                        zones.append({
                            'vrf_name': vrf_name
                        })

                serializer = GetZoneSerializer(zones, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response({'status': 'error', 'message': 'Failed to retrieve zone data'}, status=status.HTTP_400_BAD_REQUEST)

        except requests.RequestException as e:
            return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CreateZoneView(APIView):
    def post(self, request):
        serializer = ZoneSerializer(data=request.data)
        if serializer.is_valid():
            zone_name = serializer.validated_data['zone_name']
            cisco_token = get_cisco_token()  # Replace with actual token retrieval logic
            base_tenant = 'development'  # Replace with actual tenant retrieval logic
            vrf_zone_name = f"{base_tenant}-{zone_name}-vrf"
            ap_zone_name = f"{base_tenant}-{zone_name}-ap"

            vrf_list_flag = get_vrf_list(cisco_token, base_tenant)
            ap_list_flag = get_ap_list(cisco_token, base_tenant)

            if vrf_zone_name in vrf_list_flag or ap_zone_name in ap_list_flag:
                messages = 'Zone already exists with the same name'
                return Response({'status': 'error', "message": messages}, status=status.HTTP_400_BAD_REQUEST)

            headers = {
                "Cookie": f"APIC-cookie={cisco_token}"
            }

            headers = {"Cookie": f"APIC-cookie={cisco_token}"}
            vrf_creation_url = f"https://172.31.1.11/api/node/mo/uni/tn-{base_tenant}.json"
            ap_creation_url = f"https://172.31.1.11/api/node/mo/uni/tn-{base_tenant}.json"

            try:
                # Create VRF
                vrf_payload = {"fvCtx": {"attributes": {"name": vrf_zone_name}}}
                vrf_response = requests.post(vrf_creation_url, headers=headers, json=vrf_payload, verify=False)

                if vrf_response.status_code != 200:
                    return Response({'status': 'error', 'message': 'Failed to create VRF'}, status=status.HTTP_400_BAD_REQUEST)

                # Create AP
                ap_payload = {"fvAp": {"attributes": {"name": ap_zone_name}}}
                ap_response = requests.post(ap_creation_url, headers=headers, json=ap_payload, verify=False)

                if ap_response.status_code == 200:
                    return Response({'status': 'success', 'message': f"Zone created successfully - {vrf_zone_name}"})
                else:
                    # Rollback VRF creation if AP creation fails
                    rollback_vrf_url = f"https://172.31.1.11/api/node/mo/uni/tn-{base_tenant}/ctx-{vrf_zone_name}.json"
                    requests.delete(rollback_vrf_url, headers=headers, verify=False)
                    return Response({'status': 'error', 'message': 'Failed to create AP and rolled back VRF creation'}, status=status.HTTP_400_BAD_REQUEST)
            except requests.RequestException as e:
                return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
