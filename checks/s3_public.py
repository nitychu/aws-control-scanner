import boto3
from botocore.exceptions import ClientError


def run(session):
    """CIS 2.1.5 — Ensure S3 buckets block public access."""
    s3 = session.client("s3")
    findings = []

    buckets = s3.list_buckets()["Buckets"]

    for bucket in buckets:
        name = bucket["Name"]

        try:
            config = s3.get_public_access_block(Bucket=name)
            block = config["PublicAccessBlockConfiguration"]
            all_blocked = all([
                block["BlockPublicAcls"],
                block["IgnorePublicAcls"],
                block["BlockPublicPolicy"],
                block["RestrictPublicBuckets"],
            ])
            status = "PASS" if all_blocked else "FAIL"
            evidence = f"public access block settings: {block}"

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                status = "FAIL"
                evidence = "no public access block configuration exists"
            else:
                status = "ERROR"
                evidence = str(e)

        findings.append({
            "control_id": "CIS-2.1.5",
            "title": "S3 buckets block public access",
            "status": status,
            "resource": f"arn:aws:s3:::{name}",
            "evidence": evidence,
            "severity": "CRITICAL",
        })

    return findings
