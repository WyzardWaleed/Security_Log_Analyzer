import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path("data/sample_auth.log")
REPORT_FILE = Path("reports/security_report.json")
FAILED_LOGIN_PATTERN = r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"

def find_failed_logins(log_file):
    failed_ips = Counter()

    for line in log_file.read_text(encoding="utf-8").splitlines():
        match = re.search(FAILED_LOGIN_PATTERN, line)

        if match:
            ip_address = match.group(1)
            failed_ips[ip_address] += 1

    return failed_ips

def get_severity(attempts):
    if attempts >= 3:
        return "HIGH"
    return "MEDIUM"

def create_report(failed_ips):
    alerts = []

    for ip_address, attempts in failed_ips.most_common():
        alerts.append({
            "source_ip": ip_address,
            "failed_login_attempts": attempts,
            "severity": get_severity(attempts),
            "detection_reason": "Repeated failed SSH login attempts",
            "recommended_action": "Review account activity and block the IP if unauthorized."
        })

    return {
        "report_generated_utc": datetime.now(timezone.utc).isoformat(),
        "tool_name": "Security Log Analyzer",
        "alert_count": len(alerts),
        "alerts": alerts
    }

def save_report(report):
    REPORT_FILE.parent.mkdir(exist_ok=True)

    with REPORT_FILE.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=4)

def main():
    failed_ips = find_failed_logins(LOG_FILE)
    report = create_report(failed_ips)
    save_report(report)

    print("Security Log Analysis Report")
    print("-" * 30)

    for alert in report["alerts"]:
        print(
            f'[{alert["severity"]}] {alert["source_ip"]}: '
            f'{alert["failed_login_attempts"]} failed login attempts'
        )

    print(f"\nSaved JSON report to: {REPORT_FILE}")

if __name__ == "__main__":
    main()