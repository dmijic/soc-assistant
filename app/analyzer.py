from collections import defaultdict
from pydantic import BaseModel
from app.log_parser import LogEntry

SUSPICIOUS_UA = ["Nikto", "sqlmap", "zgrab", "python-requests", "masscan"]

class AnomalyReport(BaseModel):
    type: str          # "brute_force", "scanner", "path_traversal"...
    severity: str      # "low", "medium", "high", "critical"
    source_ip: str
    description: str
    count: int         # koliko puta se pojavilo
    examples: list[str]  # primjeri log linija

def analyze(entries: list[LogEntry]) -> list[AnomalyReport]:
    # PROLAZ 1 — skupi statistike
    login_attempts = defaultdict(list)   # ip -> lista entry objekata
    scanner_entries = []                  # entries sa suspicious UA
    traversal_entries = []               # entries s path traversal
    sensitive_entries = []               # entries sa sensitive pathovima
    flood_404 = defaultdict(list)        # ip -> lista 404 entry objekata

    for entry in entries:
        if entry.path in ["/wp-login.php", "/login", "/admin"] and entry.method == "POST":
            login_attempts[entry.ip].append(entry)
        if any(ua in entry.user_agent for ua in SUSPICIOUS_UA):
            scanner_entries.append(entry)
        if "../" in entry.path or "etc/passwd" in entry.path or "cmd=" in entry.path:
            traversal_entries.append(entry)
        if ".env" in entry.path or "wp-config.php" in entry.path or "shell.php" in entry.path:
            sensitive_entries.append(entry)
        if entry.status_code == 404:
            flood_404[entry.ip].append(entry)

    # PROLAZ 2 — odluči što je anomalija
    reports = []
    
    # brute force: ip s > 10 login pokušaja
    for ip, attempts in login_attempts.items():
        if len(attempts) > 10:
            # kreiraj AnomalyReport
            report = AnomalyReport(
                type="brute_force",
                severity="high",
                source_ip=ip,
                description=f"Detected {len(attempts)} login attempts from {ip}.",
                count=len(attempts),
                examples=[f"{a.timestamp} {a.method} {a.path}" for a in attempts[:5]]
            )
            reports.append(report)

    # scanner: ip s > 5 suspicious UA
    scanner_ips = defaultdict(list)
    for entry in scanner_entries:
        scanner_ips[entry.ip].append(entry)
    for ip, hits in scanner_ips.items():
        if len(hits) > 5:
            report = AnomalyReport(
                type="scanner",
                severity="medium",
                source_ip=ip,
                description=f"Detected {len(hits)} requests with suspicious user agents from {ip}.",
                count=len(hits),
                examples=[f"{e.timestamp} {e.method} {e.path} {e.user_agent}" for e in hits[:5]]
            )
            reports.append(report)

    # path traversal: ip s > 3 path traversal attempts
    traversal_ips = defaultdict(list)
    for entry in traversal_entries:
        traversal_ips[entry.ip].append(entry)
    for ip, hits in traversal_ips.items():       
        if len(hits) > 3:
            report = AnomalyReport(
                type="path_traversal",
                severity="high",
                source_ip=ip,
                description=f"Detected {len(hits)} path traversal attempts from {ip}.",
                count=len(hits),
                examples=[f"{e.timestamp} {e.method} {e.path}" for e in hits[:5]]
            )
            reports.append(report)

    # sensitive file access: ip s > 2 sensitive file attempts
    sensitive_ips = defaultdict(list)
    for entry in sensitive_entries:
        sensitive_ips[entry.ip].append(entry)
    for ip, hits in sensitive_ips.items():
        if len(hits) > 2:
            report = AnomalyReport(
                type="sensitive_file_access",
                severity="critical",
                source_ip=ip,
                description=f"Detected {len(hits)} attempts to access sensitive files from {ip}.",
                count=len(hits),
                examples=[f"{e.timestamp} {e.method} {e.path}" for e in hits[:5]]
            )
            reports.append(report)

    # flood 404: ip s > 20 404 responses
    for ip, hits in flood_404.items():
        if len(hits) > 20:
            report = AnomalyReport(
                type="flood_404",
                severity="medium",
                source_ip=ip,
                description=f"Detected {len(hits)} 404 responses from {ip}.",
                count=len(hits),
                examples=[f"{e.timestamp} {e.method} {e.path}" for e in hits[:5]]
            )
            reports.append(report)
    
    return reports
