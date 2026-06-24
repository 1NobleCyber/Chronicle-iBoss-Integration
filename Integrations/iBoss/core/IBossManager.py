"""
iBossManager for the iBoss Google SecOps SOAR Integration.

Handles all API interactions with the iBoss Cloud Gateway.
"""

import requests
import json
import base64
from urllib.parse import urlencode

class IBossAuthenticationError(Exception):
    """Exception raised for authentication errors."""
    pass

class IBossConnectionError(Exception):
    """Exception raised for connection errors."""
    pass

class IBossManager:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.auth_token = None
        self.cookies = None
        self.xsrf_token = None
        self.account_id = None
        self.gateway_dns = None
        self.reporting_dns = None
        self.gateway_version = None
        self.session = requests.Session()

    def connect(self):
        """Authenticates with the iBoss API and retrieves connection details."""
        login_uri = "/ibossauth/web/tokens?ignoreAuthModule=true"
        full_login_url = f"https://accounts.iboss.com{login_uri}"
        
        plain_auth = f"{self.username}:{self.password}"
        basic_auth = base64.b64encode(plain_auth.encode('iso-8859-1')).decode('utf-8')
        
        headers = {
            "Authorization": f"Basic {basic_auth}",
            "User-Agent": "ibossAPI",
            "Accept": "application/json"
        }
        
        try:
            response = self.session.get(full_login_url, headers=headers)
        except requests.RequestException as e:
            raise IBossConnectionError(f"Failed to connect to iBoss authentication endpoint: {e}")
        
        if response.status_code >= 400:
            raise IBossAuthenticationError(f"Login failed: {response.text}")
            
        try:
            token_obj = response.json()
            raw_token = token_obj.get("token", token_obj)
            self.auth_token = f"Token {raw_token}"
        except ValueError:
            raise IBossAuthenticationError("Failed to parse authentication response.")
        
        # Parse cookies for XSRF token
        self.cookies = response.cookies
        for cookie in self.cookies:
            if cookie.name == 'XSRF-TOKEN':
                self.xsrf_token = cookie.value
                
        # Step 2: Get Account Context
        my_settings = self._request("Core", "/ibcloud/web/users/mySettings")
        if isinstance(my_settings, list) and len(my_settings) > 0:
            my_settings = my_settings[0]
        self.account_id = my_settings.get("accountSettingsId") or my_settings.get("id")
        
        # Step 3: Get Cloud Nodes
        cloud_nodes = self._request("Core", f"/ibcloud/web/cloudNodes?accountSettingsId={self.account_id}")
        
        primary_node = next((n for n in cloud_nodes if n.get("primaryNode") == 1), None)
        if not primary_node:
            primary_node = next((n for n in cloud_nodes if n.get("masterAdminInterfaceDns")), None)
            
        if primary_node and primary_node.get("masterAdminInterfaceDns"):
            self.gateway_dns = f"https://{primary_node['masterAdminInterfaceDns']}"
            self.gateway_version = primary_node.get("currentFirmwareVersion")
        else:
            raise IBossConnectionError("Could not identify a Primary Gateway DNS.")

    def test_connectivity(self):
        """Tests the connection by authenticating."""
        self.connect()
        return True

    def _request(self, service, uri, method="GET", body=None, extra_headers=None):
        if service == "Core":
            base_url = "https://api.ibosscloud.com"
        elif service == "Gateway":
            base_url = self.gateway_dns
        elif service == "Reporting":
            raise ValueError("Reporting service is not supported in this action.")
        else:
            raise ValueError(f"Unknown service {service}")
            
        url = f"{base_url}/{uri.lstrip('/')}"
        
        headers = {
            "User-Agent": "ibossAPI",
            "Authorization": self.auth_token,
            "Content-Type": "application/json;charset=UTF-8"
        }
        if self.xsrf_token:
            headers["X-XSRF-TOKEN"] = self.xsrf_token
            
        if extra_headers:
            headers.update(extra_headers)
            
        req_args = {"url": url, "headers": headers}
        if body is not None:
            req_args["json"] = body
            
        try:
            if method == "GET":
                res = self.session.get(**req_args)
            elif method == "POST":
                res = self.session.post(**req_args)
            elif method == "PUT":
                res = self.session.put(**req_args)
            else:
                res = self.session.request(method, **req_args)
                
            res.raise_for_status()
        except requests.RequestException as e:
            raise IBossConnectionError(f"API request failed: {e}")
        
        try:
            return res.json()
        except Exception:
            return res.text

    def block_url(self, url, note="", policy_id=1):
        """Blocks a given URL by adding it to the blocklist."""
        uri = f"/json/controls/blockList?currentPolicyBeingEdited={policy_id}"
        payload = {
            "global": 0,
            "isRegex": 0,
            "direction": 2,
            "priority": 0,
            "currentPolicyBeingEdited": policy_id,
            "startPort": None,
            "endPort": None,
            "urlFieldType": 0,
            "url": url,
            "note": note
        }
        
        return self._request("Gateway", uri, method="PUT", body=payload)
