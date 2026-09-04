import boto3


def run(session):
    """CIS 2.2.1 — Ensure EBS volumes are encrypted at rest."""
    ec2 = session.client("ec2")
    findings = []

    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate():
        for volume in page["Volumes"]:
            encrypted = volume["Encrypted"]

            findings.append({
                "control_id": "CIS-2.2.1",
                "title": "EBS volumes encrypted at rest",
                "status": "PASS" if encrypted else "FAIL",
                "resource": volume["VolumeId"],
                "evidence": f"Encrypted={encrypted}, state={volume['State']}",
                "severity": "HIGH",
            })

    return findings
