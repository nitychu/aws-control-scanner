import boto3
import controls

def run(session):
    """CIS 1.10 — Ensure MFA is enabled for all IAM users with a console password."""
    iam = session.client("iam")
    findings = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            name = user["UserName"]
            try:
                iam.get_login_profile(UserName=name)
            except iam.exceptions.NoSuchEntityException:
                continue
            devices = iam.list_mfa_devices(UserName=name)["MFADevices"]
            control = controls.get("CIS-1.10")
            findings.append({
                "control_id": "CIS-1.10",
                "title": control["title"],
                "status": "PASS" if devices else "FAIL",
                "resource": user["Arn"],
                "evidence": f"list_mfa_devices returned {len(devices)} device(s)",
                "severity": control["severity"],
                "frameworks": control["frameworks"],
            })

    return findings
