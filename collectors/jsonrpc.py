import requests
from requests_gssapi import HTTPSPNEGOAuth
from dataclasses import dataclass

@dataclass
class IPAJsonRPCConfig:
    base_url: str  # e.g. https://ipa.example.com
    verify_tls: bool = True

class IPAJsonRPC:
    def __init__(self, cfg: IPAJsonRPCConfig, use_kerberos: bool = True, username: str = None, password: str = None):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.verify = cfg.verify_tls
        self.headers = {"Referer": f"{cfg.base_url}/ipa", "Accept": "application/json", "Content-Type": "application/json"}
        self.use_kerberos = use_kerberos
        self.username = username
        self.password = password

    def login(self):
        if self.use_kerberos:
            # Assumes a valid TGT in cache or use KRB5_CLIENT_KTNAME for keytab
            self.session.auth = HTTPSPNEGOAuth()
            # Touch the session endpoint to establish cookie
            r = self.session.get(f"{self.cfg.base_url}/ipa/session/login_kerberos", headers={"Accept": "text/plain"})
            r.raise_for_status()
            return True
        else:
            data = {"user": self.username, "password": self.password}
            r = self.session.post(f"{self.cfg.base_url}/ipa/session/login_password", data=data, headers={"Accept": "text/plain"})
            r.raise_for_status()
            return True

    def call(self, method: str, params: list = None, options: dict = None, version: str = "2.251"):
        if params is None:
            params = [[]]
        if options is None:
            options = {}
        payload = {"id": 0, "method": method, "params": [params, {**options, "version": version}]}
        r = self.session.post(f"{self.cfg.base_url}/ipa/session/json", json=payload, headers=self.headers)
        r.raise_for_status()
        return r.json()

    # convenience wrappers
    def user_find(self, sizelimit=50):
        return self.call("user_find", [""], {"all": True, "sizelimit": sizelimit})

    def pwpolicy_show(self, cn="global_policy"):
        return self.call("pwpolicy_show", [cn], {"all": True})

    def hbacrule_find(self, sizelimit=200):
        return self.call("hbacrule_find", [""], {"all": True, "sizelimit": sizelimit})

    def sudorule_find(self, sizelimit=200):
        return self.call("sudorule_find", [""], {"all": True, "sizelimit": sizelimit})

    def role_find(self, sizelimit=200):
        return self.call("role_find", [""], {"all": True, "sizelimit": sizelimit})

