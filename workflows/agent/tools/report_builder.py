"""
Report Builder Tool for Google ADK Agent

This tool builds comprehensive vulnerability analysis reports from
CVE information and code search findings.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class VulnerabilityFinding(BaseModel):
    """Individual vulnerability finding"""
    
    file_path: str = Field(description="Path to the vulnerable file")
    line_number: int = Field(description="Line number of the vulnerability")
    method_name: str = Field(description="Vulnerable method/function name")
    code_snippet: str = Field(description="Code snippet showing the vulnerability")
    exploitable: bool = Field(description="Whether this is exploitable")
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence level (0.0 to 1.0)"
    )
    explanation: str = Field(description="Explanation of the finding")


class VulnerabilityReport(BaseModel):
    """Complete vulnerability analysis report"""
    
    job_id: str = Field(description="Job/analysis identifier")
    cve_id: str = Field(description="CVE identifier")
    timestamp: str = Field(description="Report generation timestamp")
    
    # Overall status
    status: str = Field(
        description="Analysis status: VULNERABLE, NOT_VULNERABLE, or UNKNOWN"
    )
    
    # CVE information
    cve_summary: str = Field(description="CVE summary")
    cve_severity: Optional[str] = Field(
        default=None,
        description="CVE severity rating"
    )
    cve_score: Optional[float] = Field(
        default=None,
        description="CVSS score if available"
    )
    
    # Repository information
    repository_url: Optional[str] = Field(
        default=None,
        description="Repository URL analyzed"
    )
    branch: Optional[str] = Field(
        default=None,
        description="Branch analyzed"
    )
    
    # Findings
    findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of vulnerability findings"
    )
    total_findings: int = Field(
        default=0,
        description="Total number of findings"
    )
    exploitable_findings: int = Field(
        default=0,
        description="Number of exploitable findings"
    )
    
    # Recommendations
    recommendations: List[str] = Field(
        default_factory=list,
        description="Fix recommendations"
    )
    
    # Additional metadata
    files_analyzed: int = Field(
        default=0,
        description="Number of files analyzed"
    )
    analysis_time_seconds: Optional[float] = Field(
        default=None,
        description="Analysis duration in seconds"
    )


def report_builder_tool(
    job_id: str,
    cve_info: Dict[str, Any],
    code_findings: Dict[str, Any],
    repository_url: Optional[str] = None,
    branch: Optional[str] = None
) -> Dict[str, Any]:
    """
    Build a comprehensive vulnerability analysis report.
    
    Takes CVE information and code search findings to generate a structured
    report with vulnerability status, detailed findings, and fix recommendations.
    
    Args:
        job_id: Unique identifier for this analysis job
        cve_info: CVE information dictionary from cve_lookup_tool
        code_findings: Code search results from code_search_tool
        repository_url: Optional URL of the analyzed repository
        branch: Optional branch name that was analyzed
    
    Returns:
        Dictionary containing the complete vulnerability report:
        - Overall vulnerability status (VULNERABLE/NOT_VULNERABLE/UNKNOWN)
        - CVE details (summary, severity, score)
        - List of findings with file paths and line numbers
        - Fix recommendations
        - Metadata (files analyzed, analysis time, etc.)
    
    Example:
        >>> cve_info = cve_lookup_tool("CVE-2022-40897")
        >>> findings = code_search_tool(code_index, "unsafe_method")
        >>> report = report_builder_tool(
        ...     job_id="job-123",
        ...     cve_info=cve_info,
        ...     code_findings=findings,
        ...     repository_url="https://github.com/user/repo"
        ... )
        >>> print(report["status"])
    """
    
    try:
        # Extract CVE information
        cve_id = cve_info.get("cve_id", "UNKNOWN")
        cve_summary = cve_info.get("summary", "No summary available")
        cve_severity = cve_info.get("severity")
        cve_score = cve_info.get("cvss_score")
        affected_packages = cve_info.get("affected_packages", [])
        vulnerable_methods = cve_info.get("vulnerable_methods", [])
        
        # Extract code findings
        findings_list = code_findings.get("findings", [])
        total_findings = code_findings.get("total_findings", 0)
        files_searched = code_findings.get("files_searched", 0)
        
        # Count exploitable findings
        exploitable_count = sum(
            1 for f in findings_list 
            if f.get("exploitable", False)
        )
        
        # Determine overall status
        if exploitable_count > 0:
            status = "VULNERABLE"
        elif total_findings > 0:
            status = "POTENTIALLY_VULNERABLE"
        else:
            status = "NOT_VULNERABLE"
        
        # Generate recommendations
        recommendations = generate_recommendations(
            cve_info=cve_info,
            findings=findings_list,
            status=status
        )
        
        # Build the report
        report = VulnerabilityReport(
            job_id=job_id,
            cve_id=cve_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            status=status,
            cve_summary=cve_summary,
            cve_severity=cve_severity,
            cve_score=cve_score,
            repository_url=repository_url,
            branch=branch,
            findings=findings_list,
            total_findings=total_findings,
            exploitable_findings=exploitable_count,
            recommendations=recommendations,
            files_analyzed=files_searched
        )
        
        # Convert to dictionary and add success flag
        result = report.model_dump()
        result["success"] = True
        result["error"] = None
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Error generating report: {str(e)}",
            "job_id": job_id,
            "cve_id": cve_info.get("cve_id", "UNKNOWN"),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "status": "ERROR",
            "cve_summary": "",
            "cve_severity": None,
            "cve_score": None,
            "repository_url": repository_url,
            "branch": branch,
            "findings": [],
            "total_findings": 0,
            "exploitable_findings": 0,
            "recommendations": [],
            "files_analyzed": 0
        }


def generate_recommendations(
    cve_info: Dict[str, Any],
    findings: List[Dict[str, Any]],
    status: str
) -> List[str]:
    """
    Generate fix recommendations based on CVE info and findings.
    """
    
    recommendations = []
    
    cve_id = cve_info.get("cve_id", "")
    affected_packages = cve_info.get("affected_packages", [])
    vulnerable_methods = cve_info.get("vulnerable_methods", [])
    references = cve_info.get("references", [])
    
    # Recommendation 1: Update affected packages
    if affected_packages:
        for pkg in affected_packages[:3]:  # Limit to first 3 packages
            package_name = pkg.get("package", "unknown")
            ecosystem = pkg.get("ecosystem", "")
            
            recommendations.append(
                f"Update {package_name} ({ecosystem}) to a patched version. "
                f"Check the package documentation for the latest secure version."
            )
    
    # Recommendation 2: Replace vulnerable method calls
    if findings and vulnerable_methods:
        unique_methods = set(f.get("method_name") for f in findings)
        for method in list(unique_methods)[:3]:  # Limit to first 3
            recommendations.append(
                f"Replace all calls to '{method}' with a secure alternative. "
                f"Review the code at the identified locations and implement proper input validation."
            )
    
    # Recommendation 3: Add security controls
    exploitable_findings = [f for f in findings if f.get("exploitable", False)]
    if exploitable_findings:
        recommendations.append(
            "Add input validation and sanitization at all entry points where user data "
            "flows into the vulnerable methods. Implement whitelist-based validation where possible."
        )
    
    # Recommendation 4: Code review
    if findings:
        recommendations.append(
            f"Conduct a thorough security code review of all {len(findings)} identified "
            f"location(s) to ensure no exploitable paths remain."
        )
    
    # Recommendation 5: Security testing
    if status == "VULNERABLE":
        recommendations.append(
            "Implement security testing (SAST/DAST) in your CI/CD pipeline to prevent "
            "similar vulnerabilities in the future."
        )
    
    # Recommendation 6: Monitor references
    if references:
        recommendations.append(
            f"Review the official CVE references for {cve_id} for detailed mitigation strategies: "
            f"{references[0] if references else 'N/A'}"
        )
    
    # If no vulnerabilities found
    if status == "NOT_VULNERABLE":
        recommendations.append(
            f"No instances of {cve_id} were detected in the analyzed code. "
            "However, ensure all dependencies are up to date and continue monitoring for security updates."
        )
    
    return recommendations


def format_report_as_markdown(report: Dict[str, Any]) -> str:
    """
    Format the report as markdown for human readability.
    """
    
    md = f"""# Vulnerability Analysis Report

## Overview

- **Job ID**: {report['job_id']}
- **CVE**: {report['cve_id']}
- **Status**: **{report['status']}**
- **Generated**: {report['timestamp']}

## CVE Information

- **Summary**: {report['cve_summary']}
- **Severity**: {report.get('cve_severity', 'N/A')}
- **CVSS Score**: {report.get('cve_score', 'N/A')}

## Repository Information

- **URL**: {report.get('repository_url', 'N/A')}
- **Branch**: {report.get('branch', 'N/A')}

## Analysis Results

- **Total Findings**: {report['total_findings']}
- **Exploitable Findings**: {report['exploitable_findings']}
- **Files Analyzed**: {report['files_analyzed']}

"""
    
    # Add findings
    if report['findings']:
        md += "## Findings\n\n"
        for i, finding in enumerate(report['findings'], 1):
            md += f"### Finding {i}\n\n"
            md += f"- **File**: `{finding['file_path']}`\n"
            md += f"- **Line**: {finding['line_number']}\n"
            md += f"- **Method**: `{finding['method_name']}`\n"
            md += f"- **Exploitable**: {'⚠️ Yes' if finding.get('exploitable') else '✓ No'}\n"
            md += f"- **Confidence**: {finding.get('confidence', 0.0):.1%}\n"
            md += f"- **Explanation**: {finding.get('explanation', 'N/A')}\n\n"
            
            if finding.get('code_snippet'):
                md += f"**Code Snippet**:\n```\n{finding['code_snippet']}\n```\n\n"
    else:
        md += "## Findings\n\nNo vulnerabilities detected.\n\n"
    
    # Add recommendations
    if report['recommendations']:
        md += "## Recommendations\n\n"
        for i, rec in enumerate(report['recommendations'], 1):
            md += f"{i}. {rec}\n"
    
    return md


# Tool metadata for Google ADK
report_builder_tool.__annotations__["return"] = str
report_builder_tool.__doc__ = """
Build a comprehensive vulnerability analysis report.

Use this tool to generate a structured report from CVE information and code findings.
The report includes vulnerability status, detailed findings with file paths and line numbers,
exploitability assessment, and actionable fix recommendations.

Args:
    job_id: Unique job identifier for this analysis
    cve_info: CVE information dictionary (from cve_lookup_tool)
    code_findings: Code search results (from code_search_tool)
    repository_url: Optional repository URL
    branch: Optional branch name

Returns:
    Complete vulnerability report with status, findings, and recommendations.
"""
