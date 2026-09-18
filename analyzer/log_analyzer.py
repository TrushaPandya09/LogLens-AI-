import re
from collections import Counter


LEVEL_PATTERN = re.compile(r"\b(INFO|WARNING|ERROR)\b", re.IGNORECASE)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FAILED_LOGIN_PATTERN = re.compile(
    r"(?:failed|failure|authentication failure|invalid password|login denied)",
    re.IGNORECASE,
)
SUCCESSFUL_LOGIN_PATTERN = re.compile(
    r"(?:successful login|login successful|accepted password|authenticated)",
    re.IGNORECASE,
)


def _valid_ip(ip_address):
    """Keep the simple IPv4 matches within valid octet ranges."""
    return all(0 <= int(octet) <= 255 for octet in ip_address.split("."))


def analyze_log(log_text):
    """Return beginner-friendly statistics and observations for supplied log text."""
    lines = [line.strip() for line in log_text.splitlines() if line.strip()]
    level_counts = Counter()
    ip_counts = Counter()
    failed_ip_counts = Counter()
    failed_logins = 0
    successful_logins = 0
    important_events = []

    for line in lines:
        level_match = LEVEL_PATTERN.search(line)
        if level_match:
            level_counts[level_match.group(1).upper()] += 1

        ips_in_line = {
            match.group(0)
            for match in IP_PATTERN.finditer(line)
            if _valid_ip(match.group(0))
        }
        ip_counts.update(ips_in_line)

        if FAILED_LOGIN_PATTERN.search(line):
            failed_logins += 1
            failed_ip_counts.update(ips_in_line)
            if len(important_events) < 8:
                important_events.append({"type": "failed", "text": line})
        elif SUCCESSFUL_LOGIN_PATTERN.search(line):
            successful_logins += 1

    top_ips = [
        {"ip": ip_address, "count": count}
        for ip_address, count in ip_counts.most_common(5)
    ]
    frequent_ips = [
        {"ip": ip_address, "count": count}
        for ip_address, count in ip_counts.most_common()
        if count >= 3
    ]

    observations = []
    security_findings = []
    if failed_logins >= 3:
        observations.append("Multiple failed login attempts detected.")
        failed_ip = failed_ip_counts.most_common(1)
        security_findings.append(
            {
                "detection": (
                    "Multiple failed login attempts detected from the same IP."
                    if failed_ip
                    else "Multiple failed login attempts detected."
                ),
                "severity": "HIGH",
                "source_ip": failed_ip[0][0] if failed_ip else None,
                "event_count": failed_ip[0][1] if failed_ip else failed_logins,
                "action": (
                    "Review the authentication events associated with this IP "
                    "and verify whether the activity is legitimate."
                ),
            }
        )
    elif failed_logins:
        observations.append("A failed login attempt was detected.")
        failed_ip = failed_ip_counts.most_common(1)
        security_findings.append(
            {
                "detection": "Authentication failure detected.",
                "severity": "MEDIUM",
                "source_ip": failed_ip[0][0] if failed_ip else None,
                "event_count": failed_logins,
                "action": (
                    "Review the related authentication events and verify the "
                    "affected account and source."
                ),
            }
        )
    else:
        observations.append("No significant failed-login pattern detected.")

    if frequent_ips:
        observations.append(
            "A frequently occurring source IP was observed: "
            f"{frequent_ips[0]['ip']} ({frequent_ips[0]['count']} events)."
        )
        security_findings.append(
            {
                "detection": "A source IP appears repeatedly in the analyzed logs.",
                "severity": "MEDIUM",
                "source_ip": frequent_ips[0]["ip"],
                "event_count": frequent_ips[0]["count"],
                "action": (
                    "Review the events associated with this IP and investigate "
                    "unusual activity or unexpected access patterns."
                ),
            }
        )
    if level_counts["ERROR"]:
        observations.append(
            f"{level_counts['ERROR']} error event"
            f"{'s' if level_counts['ERROR'] != 1 else ''} require review."
        )
        security_findings.append(
            {
                "detection": (
                    "Multiple application or system errors detected."
                    if level_counts["ERROR"] > 1
                    else "An application or system error was detected."
                ),
                "severity": "MEDIUM" if level_counts["ERROR"] > 1 else "LOW",
                "source_ip": None,
                "event_count": level_counts["ERROR"],
                "action": (
                    "Review the associated error events and determine whether "
                    "they indicate a configuration, application, or security issue."
                ),
            }
        )
    if not security_findings:
        security_findings.append(
            {
                "detection": "No significant suspicious pattern detected.",
                "severity": "LOW",
                "source_ip": None,
                "event_count": None,
                "action": (
                    "No immediate suspicious pattern was identified. Continue "
                    "monitoring the relevant log activity."
                ),
            }
        )

    return {
        "total_events": len(lines),
        "info_events": level_counts["INFO"],
        "warning_events": level_counts["WARNING"],
        "error_events": level_counts["ERROR"],
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "unique_ips": len(ip_counts),
        "top_ips": top_ips,
        "frequent_ips": frequent_ips,
        "important_events": important_events,
        "observations": observations,
        "security_findings": security_findings,
    }
