from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any


@dataclass
class ScanResult:
    url: str
    start_time: str
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    error: Optional[str] = None
    discovered_pages: List[str] = field(default_factory=list)
    note: Optional[str] = None
    form_info: Optional[Dict[str, Any]] = None
    tests: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    baseline_login: Optional[Dict[str, Any]] = None
    username_enumeration: Optional[Dict[str, Any]] = None
    captcha_detected: Optional[bool] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "url": self.url,
            "start_time": self.start_time,
            "tests": self.tests,
            "summary": self.summary
        }
        
        if self.end_time:
            result["end_time"] = self.end_time
        if self.duration_seconds:
            result["duration_seconds"] = self.duration_seconds
        if self.error:
            result["error"] = self.error
        if self.discovered_pages:
            result["discovered_pages"] = self.discovered_pages
        if self.note:
            result["note"] = self.note
        if self.form_info:
            result["form_info"] = self.form_info
        if self.baseline_login:
            result["baseline_login"] = self.baseline_login
        if self.username_enumeration:
            result["username_enumeration"] = self.username_enumeration
        if self.captcha_detected is not None:
            result["captcha_detected"] = self.captcha_detected
            
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanResult':
        return cls(
            url=data.get("url", ""),
            start_time=data.get("start_time", datetime.now().isoformat()),
            end_time=data.get("end_time"),
            duration_seconds=data.get("duration_seconds", 0.0),
            error=data.get("error"),
            discovered_pages=data.get("discovered_pages", []),
            note=data.get("note"),
            form_info=data.get("form_info"),
            tests=data.get("tests", {}),
            summary=data.get("summary", {}),
            baseline_login=data.get("baseline_login"),
            username_enumeration=data.get("username_enumeration"),
            captcha_detected=data.get("captcha_detected")
        )

