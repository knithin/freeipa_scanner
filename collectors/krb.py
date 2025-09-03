import subprocess
import re

class KerberosChecks:
    def __init__(self, realm=None, kdc_host=None):
        self.realm = realm
        self.kdc_host = kdc_host

    def kinit_with_keytab(self, principal, keytab):
        cmd = ["kinit", "-k", "-t", keytab, principal]
        r = subprocess.run(cmd, capture_output=True, text=True)
        return r.returncode, r.stderr or r.stdout

    def klist_tickets(self):
        r = subprocess.run(["klist"], capture_output=True, text=True)
        return r.stdout

    def kvno_service(self, spn):
        r = subprocess.run(["kvno", spn], capture_output=True, text=True)
        return r.returncode, r.stderr or r.stdout

    def parse_enctypes_from_klist(self, klist_output):
        # naive parse of encryption types from tickets
        return re.findall(r"etype\s+\(skey\):\s+([A-Za-z0-9\-]+)", klist_output)

