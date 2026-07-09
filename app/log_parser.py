import re
from pydantic import BaseModel

class LogEntry(BaseModel):
    ip: str
    timestamp: str
    method: str
    path: str
    status_code: int
    size: int
    user_agent: str

def parse_line(line: str) -> LogEntry | None:
    log_pattern = re.compile(
        r'(?P<ip>\S+) - - \[(?P<timestamp>.*?)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status_code>\d+) (?P<size>\S+) "(?P<user_agent>.*?)"'
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
            user_agent=match.group("user_agent")
        )
    return None