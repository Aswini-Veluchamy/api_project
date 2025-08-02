import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import jsonify
import pandas as pd
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
import requests
SECRET_KEY = settings.SECRET_KEY
CISCO_AUTH_URL = "https://172.31.231.91/api/aaaLogin.json"


def user_login(domain, username, password):
    status, token, tenant_list = get_openstack_token(username, password, domain)
    if status != 201:
        return False, None
    token = jwt.encode({
        'user': username,
        'exp': datetime.utcnow() + timedelta(minutes=30),
        'openstack_token': token,
        'tenant_list': tenant_list
    }, SECRET_KEY, algorithm='HS256')
    # print(token)
    # data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    # print('token', data)
    return True, token


def token_required(func):
    @wraps(func)
    def decorated(request, *args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return Response({'message': 'Token is missing!'}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            # print(data)
            request.user = data
        except jwt.ExpiredSignatureError:
            return Response({'message': 'Token has expired!'}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError:
            return Response({'message': 'Invalid token!'}, status=status.HTTP_401_UNAUTHORIZED)
        return func(request, *args, **kwargs)
    return decorated

def get_openstack_token(username, password, domain):
    url = 'https://keystone.tcsecp.com:5000/v3/auth/tokens'
    myobj = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "domain": {"name": domain},
                        "password": password
                    }
                }
            }
        }
    }
    x = requests.post(url, json=myobj, verify=False)
    token = ''
    tenant_list = []

    if x.status_code == 201:
        token = x.headers["X-Subject-Token"]
        project_json = x.json().get("token", {}).get("project")
        if project_json:
            tenant_list.append(project_json.get("name"))
    return x.status_code, token, tenant_list

def get_cisco_token():
    login_data = {
        "aaaUser": {
            "attributes": {
                "name": "api_admin",
                "pwd": "Admin#1234"
            }
        }
    }
    login_response = requests.post(CISCO_AUTH_URL, json=login_data, verify=False)

    if login_response.status_code == 200:
        token = login_response.json()['imdata'][0]['aaaLogin']['attributes']['token']
        return token
    else:
        raise Exception('Failed to retrieve Cisco token. Please check user details.')