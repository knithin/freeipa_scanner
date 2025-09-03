import argparse, json, yaml
from collectors.jsonrpc import IPAJsonRPC, IPAJsonRPCConfig
from collectors.ldap_probe import LDAPProbe
from collectors.krb import KerberosChecks
from collectors.healthcheck import run_ipa_healthcheck
from report.render import render_pdf

def evaluate_rules(context, rules):
    findings = []
    passed = 0
    for r in rules["rules"]:
        # very simple expression evaluator for demo purposes
        expr = r["check"]
        # Map dotted paths to context values
        expr_eval = expr.replace("ldap.anonymous_bind_allowed", str(context["ldap"]["anonymous_allowed"]).lower()) \
                        .replace("ldap.uses_tls", str(context["ldap"]["uses_tls"]).lower())
        expr_eval = expr_eval.replace("jsonrpc.pwpolicy.krbpwdminlength", str(context["jsonrpc"]["pwpolicy"].get("krbpwdminlength", 0))) \
                             .replace("jsonrpc.realm.preauth", str(context["jsonrpc"].get("preauth_required", False)).lower())
        try:
            result = eval(expr_eval)
        except Exception:
            result = False
        findings.append({
            "id": r["id"],
            "title": r["title"],
            "severity": r["severity"],
            "passed": bool(result),
            "evidence": json.dumps(context, indent=2)[:2000],
            "remediation": r["remediation"]
        })
        if result:
            passed += 1
    summary = {"total": len(findings), "passed": passed, "failed": len(findings) - passed}
    return findings, summary

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ipa-url", required=True, help="https://ipa.example.com")
    ap.add_argument("--ipa-host", required=True, help="ipa.example.com")
    ap.add_argument("--base-dn", required=True, help="dc=example,dc=com")
    ap.add_argument("--kerberos", action="store_true", help="Use Kerberos for JSON-RPC")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--ldaps", action="store_true")
    ap.add_argument("--ca-cert")
    ap.add_argument("--principal")
    ap.add_argument("--keytab")
    ap.add_argument("--output", default="report.pdf")
    args = ap.parse_args()

    # JSON-RPC
    jsonrpc = IPAJsonRPC(IPAJsonRPCConfig(args.ipa_url), use_kerberos=args.kerberos, username=args.user, password=args.password)
    jsonrpc.login()
    pwpol = jsonrpc.pwpolicy_show().get("result", {}).get("result", {})
    # crude preauth detection: FreeIPA enforces preauth by default; you can refine by querying principals
    preauth_required = True

    # LDAP
    ldap_probe = LDAPProbe(args.ipa_host, args.base_dn, use_ssl=args.ldaps, ca_cert=args.ca_cert, bind_dn=args.user, password=args.password)
    ldap_probe.connect()
    anon_allowed = ldap_probe.anonymous_bind_allowed()
    uses_tls = args.ldaps

    # Kerberos
    krb = KerberosChecks()
    if args.principal and args.keytab:
        krb.kinit_with_keytab(args.principal, args.keytab)
    klist_out = krb.klist_tickets()
    enctypes = krb.parse_enctypes_from_klist(klist_out)

    # Healthcheck
    rc, hc = run_ipa_healthcheck(failures_only=True)

    context = {
        "jsonrpc": {"pwpolicy": pwpol, "preauth_required": preauth_required},
        "ldap": {"anonymous_allowed": anon_allowed, "uses_tls": uses_tls},
        "kerberos": {"enctypes": enctypes},
        "healthcheck": {"returncode": rc, "data": hc}
    }

    with open("rules/baseline.yml") as f:
        rules = yaml.safe_load(f)

    findings, summary = evaluate_rules(context, rules)
    render_pdf(findings, summary, args.output)
    print(f"Wrote report to {args.output}")

if __name__ == "__main__":
    main()

