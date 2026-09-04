import boto3
from datetime import datetime, timezone
import controls

MAX_KEY_AGE_DAYS = 90


def run(session):
    """CIS 1.14 — Ensure access keys are rotated within 90 days."""
    iam = session.client("iam")
    findings = []
    now = datetime.now(timezone.utc)

    user_pages = iam.get_paginator("list_users")
    for page in user_pages.paginate():
        for user in page["Users"]:
            name = user["UserName"]
            keys = iam.list_access_keys(UserName=name)["AccessKeyMetadata"]

            for key in keys:
                if key["Status"] != "Active":
                    continue

                age = (now - key["CreateDate"]).days
                key_id = key["AccessKeyId"]

                control = controls.get("CIS-1.14")
                findings.append({
                    "control_id": "CIS-1.14",
                    "title": control["title"],
                    "status": "FAIL" if age > MAX_KEY_AGE_DAYS else "PASS",
                    "resource": f"{name}/{key_id[-4:]}",
                    "evidence": f"key age {age} days (threshold {MAX_KEY_AGE_DAYS})",
                    "severity": control["severity"],
                    "frameworks": control["frameworks"],
                })

    return findings
