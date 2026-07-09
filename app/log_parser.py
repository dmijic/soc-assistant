import re
from pydantic import BaseModel
import os

class LogEntry(BaseModel):
    ip: str
    timestamp: str
    method: str
    path: str
    status_code: int
    size: int
    referer: str
    user_agent: str

def parse_line(line: str) -> LogEntry | None:
    log_pattern = re.compile(
        r'(?P<ip>\S+) - - \[(?P<timestamp>.*?)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status_code>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )
    
    match = log_pattern.match(line)
    if match:
        return LogEntry(
            ip=match.group("ip"),
            timestamp=match.group("timestamp"),
            method=match.group("method"),
            path=match.group("path"),
            status_code=int(match.group("status_code")),
            size=int(match.group("size")) if match.group("size") != "-" else 0,
            referer=match.group("referer"),
            user_agent=match.group("user_agent")
        )
    return None

def parse_file(path: str) -> list[LogEntry]:
    log_entries = []
    with open(path, 'r') as file:
        for line in file:
            entry = parse_line(line)
            if entry:
                log_entries.append(entry)
    return log_entries