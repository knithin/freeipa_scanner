from ldap3 import Server, Connection, Tls, ALL, SUBTREE
import ssl

class LDAPProbe:
    def __init__(self, host, base_dn, use_ssl=True, ca_cert=None, bind_dn=None, password=None):
        self.host = host
        self.base_dn = base_dn
        self.use_ssl = use_ssl
        tls = None
        if use_ssl:
            tls = Tls(validate=ssl.CERT_REQUIRED if ca_cert else ssl.CERT_NONE, ca_certs_file=ca_cert)
        self.server = Server(host, use_ssl=use_ssl, get_info=ALL, tls=tls)
        self.bind_dn = bind_dn
        self.password = password
        self.conn = None

    def connect(self):
        self.conn = Connection(self.server, user=self.bind_dn, password=self.password, auto_bind=True) if self.bind_dn else Connection(self.server, auto_bind=True)
        return self.conn.bound

    def anonymous_bind_allowed(self):
        # Try anonymous search of users container to gauge exposure
        anon_conn = Connection(self.server, auto_bind=True)
        ok = anon_conn.search(self.base_dn, "(objectClass=person)", SUBTREE, attributes=["uid"], size_limit=1)
        return ok and len(anon_conn.entries) > 0

    def read_password_policy(self):
        # Global policy stored under cn=global_policy,cn=accounts,base
        self.conn.search(self.base_dn, "(cn=global_policy)", SUBTREE, attributes=["krbminpwdlife", "krbmaxpwdlife", "krbpwdminlength", "krbpwdhistorylength", "krbpwdlockoutduration", "krbpwdmaxfailure"])
        return [e.entry_to_json() for e in self.conn.entries]

