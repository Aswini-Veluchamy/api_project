from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from openstack import connection

class OpenStackAuthentication(BaseAuthentication):
    def authenticate(self, request):
        token = request.headers.get('Authorization')
        if not token:
            return None

        try:
            conn = connection.Connection(
                auth_url='https://keystone-ovn.tcsecp.com/v3',
                project_name='a7e43815b6f54b729e7394c77e1d3afa',
                username='api_dev',
                password='Admin#1234',
                user_domain_name='admin_domain',
                project_domain_name='admin_domain'
            )

            # Validate token with OpenStack
            conn.identity.get_token_info(token)
        except Exception as e:
            raise AuthenticationFailed('Invalid token.')

        return (None, token)  # Return user and token

    def authenticate_header(self, request):
        return 'Bearer'