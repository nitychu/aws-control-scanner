import boto3
import controls 

RISKY_PORTS = {22: "SSH", 3389: "RDP"}
OPEN_CIDR = "0.0.0.0/0"


def run(session):
    """CIS 5.2 — Ensure no security group allows ingress from 0.0.0.0/0 to admin ports."""
    ec2 = session.client("ec2")
    findings = []

    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for group in page["SecurityGroups"]:
            exposed = []

            for rule in group["IpPermissions"]:
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                if from_port is None:
                    continue

                open_to_world = any(
                    r.get("CidrIp") == OPEN_CIDR for r in rule.get("IpRanges", [])
                )
                if not open_to_world:
                    continue

                for port, label in RISKY_PORTS.items():
                    if from_port <= port <= to_port:
                        exposed.append(f"{label}/{port}")

            control = controls.get("CIS-5.2")
            findings.append({
                "control_id": "CIS-5.2",
                "title": control["title"],
                "status": "FAIL" if exposed else "PASS",
                "resource": group["GroupId"],
                "evidence": (
                    f"{OPEN_CIDR} ingress to {', '.join(exposed)}"
                    if exposed
                    else "no unrestricted ingress to admin ports"
                ),
                "severity": control["severity"],
                "frameworks": control["frameworks"],
            })

    return findings
