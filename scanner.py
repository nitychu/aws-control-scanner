import boto3
from checks import iam_mfa

CHECKS = [iam_mfa]


def main():
    session = boto3.Session()
    findings = []

    for check in CHECKS:
        try:
            findings.extend(check.run(session))
        except Exception as e:
            findings.append({
                "control_id": "UNKNOWN",
                "title": check.__name__,
                "status": "ERROR",
                "resource": "n/a",
                "evidence": str(e),
                "severity": "INFO",
            })

    for f in findings:
        print(f"[{f['status']}] {f['control_id']} — {f['resource']}")


if __name__ == "__main__":
    main()

