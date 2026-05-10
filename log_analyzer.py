import re
import csv
from collections import Counter

# --------------------------------
# Configuration
# --------------------------------
LOG_FILE = "sample.log"
REPORT_FILE = "report.csv"
SUSPICIOUS_THRESHOLD = 3

# --------------------------------
# Read log file
# --------------------------------
with open(LOG_FILE, "r") as file:
    logs = file.readlines()

# --------------------------------
# Extract failed login IPs
# --------------------------------
failed_ips = []

for line in logs:
    if "Failed password" in line:
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)

        if ip_match:
            failed_ips.append(ip_match.group())

# --------------------------------
# Count failed attempts
# --------------------------------
counter = Counter(failed_ips)

# --------------------------------
# Terminal output
# --------------------------------
print("=== Security Log Analysis ===")

if counter:
    for ip, count in counter.most_common():
        print(f"{ip}: {count} failed attempts")
else:
    print("No failed login attempts found.")

# --------------------------------
# Detect suspicious IPs
# --------------------------------
print("\n=== Suspicious IPs ===")

suspicious_ips = []

for ip, count in counter.most_common():
    if count >= SUSPICIOUS_THRESHOLD:
        suspicious_ips.append(ip)
        print(f"ALERT -> {ip}")

if not suspicious_ips:
    print("No suspicious IPs detected.")

# --------------------------------
# Executive summary
# --------------------------------
total_failed_logins = len(failed_ips)
total_unique_ips = len(counter)
total_suspicious_ips = len(suspicious_ips)

if counter:
    most_active_ip, most_active_count = counter.most_common(1)[0]
else:
    most_active_ip = "None"
    most_active_count = 0

print("\n=== Executive Summary ===")
print(f"Total failed login attempts: {total_failed_logins}")
print(f"Unique IPs detected: {total_unique_ips}")
print(f"Total suspicious IPs: {total_suspicious_ips}")
print(f"Most active IP: {most_active_ip} ({most_active_count} attempts)")

# --------------------------------
# Create CSV report
# --------------------------------
with open(REPORT_FILE, "w", newline="") as report:
    writer = csv.writer(report)

    writer.writerow([
        "IP Address",
        "Failed Attempts",
        "Risk Level",
        "Recommendation"
    ])

    for ip, count in counter.most_common():

        if count >= 5:
            risk = "HIGH"
            recommendation = "Investigate immediately."

        elif count >= SUSPICIOUS_THRESHOLD:
            risk = "MEDIUM"
            recommendation = "Monitor this IP."

        else:
            risk = "LOW"
            recommendation = "No immediate action required."

        writer.writerow([
            ip,
            count,
            risk,
            recommendation
        ])

print(f"\nSecurity report saved as {REPORT_FILE}")