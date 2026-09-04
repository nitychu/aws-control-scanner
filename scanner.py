import boto3
from checks import iam_mfa, s3_public, ebs_encryption, iam_key_age, sg_open_ports
import report

CHECKS = [iam_mfa, s3_public,ebs_encryption, iam_key_age,sg_open_ports]


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

    total = len(findings)
    failed = sum(1 for f in findings if f["status"] == "FAIL")
    passed = sum(1 for f in findings if f["status"] == "PASS")
    errors = sum(1 for f in findings if f["status"] == "ERROR")

    print(f"Scanned {len(CHECKS)} control(s), evaluated {total} resource(s)")
    print(f"{passed} passed, {failed} failed, {errors} error(s)\n")

    path = report.write(findings, len(CHECKS))
    print(f"Report written to {path}\n")

    if not findings:
        print("No applicable resources found. This is not the same as compliant.")

    for f in findings:
        print(f"[{f['status']}] {f['control_id']} — {f['resource']}")
        if f["status"] != "PASS":
            print(f"    {f['evidence']}")


if __name__ == "__main__":
    main()

