from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class RiskLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class SecurityIssue(BaseModel):
    """
    Represents a single security misconfiguration finding.
    """
    title: str
    risk_level: RiskLevel
    description: str
    remediation: str
    cwe_id: Optional[str] = None

class ScanResult(BaseModel):
    """
    Encapsulates the complete results from a single target scan.
    """
    target_url: str
    scan_timestamp: str
    issues: List[SecurityIssue] = Field(default_factory=list)