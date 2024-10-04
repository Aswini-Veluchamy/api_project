from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import requests
import logging
from .config import CISCO_BASE_ROUTE_URL
from .get_token import get_cisco_token, get_openstack_token, get_cisco_tenant_list

# Configure logging
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('D://logs//logfile.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


@method_decorator(csrf_exempt, name='dispatch')
class UserLoginView(APIView):
    def post(self, request):
        domain = request.data.get("domain")
        username = request.data.get('username')
        password = request.data.get('password')
        logger.info(f"{username}: User login attempt")

        # Authenticate with OpenStack
        status_code, openstack_token, tenant_list = get_openstack_token(username, password, domain)

        # Get Cisco token
        try:
            cisco_token = get_cisco_token()
        except Exception as ex:
            logger.error(f"{username}: Failed to get Cisco token: {ex}")
            return Response({'error': str(ex)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Verify OpenStack login status
        if status_code != 201:
            logger.warning(f"{username}: Invalid credentials provided")
            return Response({'error': 'Please provide valid credentials !!!'}, status=status.HTTP_401_UNAUTHORIZED)

        # Determine base tenant
        base_tenant = tenant_list[0] if tenant_list else ''

        # Check if base tenant is in Cisco ACI tenant list
        try:
            cisco_tenant_list = get_cisco_tenant_list(cisco_token)
            if base_tenant not in cisco_tenant_list:
                logger.warning(f"{username}: Base tenant not found in Cisco ACI tenant list")
                return Response({'error': 'Base tenant not found in Cisco ACI tenant list'},
                                status=status.HTTP_404_NOT_FOUND)
        except Exception as ex:
            logger.error(f"{username}: Failed to get Cisco tenant list: {ex}")
            return Response({'error': str(ex)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        logger.info(f"{username}: Logged in successfully")

        # Retrieve zone data after successful login
        zone_data = self.get_zone_data(cisco_token, base_tenant)
        return Response({'zone_data': zone_data}, status=status.HTTP_200_OK)

    def get_zone_data(self, cisco_token, base_tenant):
        headers = {
            "Cookie": f"APIC-cookie={cisco_token}"
        }

        vrf_url = f"{CISCO_BASE_ROUTE_URL}/node/class/fvCtx.json"
        ap_url = f"{CISCO_BASE_ROUTE_URL}/node/class/fvAp.json"

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

                return zones
            else:
                raise Exception('Failed to retrieve zone data')

        except requests.RequestException as e:
            logger.error(f"Error while retrieving zone data: {str(e)}")
            raise Exception(f"Error while retrieving zone data: {str(e)}")

