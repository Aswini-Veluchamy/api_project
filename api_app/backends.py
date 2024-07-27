from django.contrib.auth.backends import BaseBackend
from openstack import connection

class OpenStackBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None):
        try:
            conn = connection.Connection(
                auth_url='https://keystone-ovn.tcsecp.com/v3',
                project_name='a7e43815b6f54b729e7394c77e1d3afa',
                username=username,
                password=password,
                user_domain_name='admin_domain',
                project_domain_name='admin_domain'
            )

            # Fetch user details or perform any other authentication logic
            user = conn.identity.find_user(username)
            if user:
                return user
        except Exception as e:
            return None

    def get_user(self, user_id):
        try:
            conn = connection.Connection(
                auth_url='https://keystone-ovn.tcsecp.com/v3',
                project_name='a7e43815b6f54b729e7394c77e1d3afa',
                username='api_dev',
                password='Admin#1234',
                user_domain_name='admin_domain',
                project_domain_name='admin_domain'
            )

            # Fetch user details by ID
            user = conn.identity.get_user(user_id)
            return user
        except Exception as e:
            return None