"""
Shared Pydantic models for the CVE Vulnerability Analysis System.

These models are used across backend, workflows, and other components
to ensure consistent data structures.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from enum import Enum


class JobStatus(str, Enum):
    """Job status enum"""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class VulnerabilityStatus(str, Enum):
    """Vulnerability assessment status"""
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    UNKNOWN = "UNKNOWN"


class CVEInfo(BaseModel):
    """CVE Information from vulnerability databases"""
    cve_id: str
    summary: str
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    affected_packages: List[str] = Field(default_factory=list)
    vulnerable_methods: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """Individual vulnerability finding in code"""
    file_path: str
    line_number: int
    method_name: str
    exploitable: bool
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    suggested_fix: str
    code_snippet: Optional[str] = None


class VulnerabilityReport(BaseModel):
    """Complete vulnerability analysis report"""
    job_id: str
    cve_id: str
    status: VulnerabilityStatus
    findings: List[Finding] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    summary: Optional[str] = None
    analyzed_at: Optional[datetime] = None


class AnalysisRequest(BaseModel):
    """Request to analyze a repository for CVE"""
    repo_url: str
    branch: str = "main"
    cve_id: str


class JobResponse(BaseModel):
    """Job status response"""
    job_id: str
    status: JobStatus
    repo_url: str
    branch: str
    cve_id: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class PackageInfo(BaseModel):
    """Package information"""
    name: str
    version: str
    ecosystem: str = "PyPI"  # PyPI, npm, Maven, etc.


class CodeIndex(BaseModel):
    """Code repository index"""
    repo_path: str
    dependencies: List[PackageInfo] = Field(default_factory=list)
    methods: Dict[str, List[int]] = Field(default_factory=dict)
    call_graph: Dict[str, List[str]] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
