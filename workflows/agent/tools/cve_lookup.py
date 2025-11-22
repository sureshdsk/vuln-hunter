"""
CVE Lookup Tool for Google ADK Agent

This tool fetches CVE vulnerability information from multiple sources:
1. OSV.dev (Primary)
2. NVD (Fallback)
"""

import requests
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class CVEInfo(BaseModel):
    """Structured CVE information model"""
    
    cve_id: str = Field(description="CVE identifier")
    summary: str = Field(description="Vulnerability summary")
    details: str = Field(description="Detailed vulnerability description")
    affected_packages: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of affected packages with version ranges"
    )
    vulnerable_methods: List[str] = Field(
        default_factory=list,
        description="Known vulnerable methods or functions"
    )
    severity: Optional[str] = Field(
        default=None,
        description="Severity rating (CRITICAL, HIGH, MEDIUM, LOW)"
    )
    cvss_score: Optional[float] = Field(
        default=None,
        description="CVSS score if available"
    )
    references: List[str] = Field(
        default_factory=list,
        description="Reference URLs for more information"
    )
    published_date: Optional[str] = Field(
        default=None,
        description="Publication date"
    )
    modified_date: Optional[str] = Field(
        default=None,
        description="Last modification date"
    )
    source: str = Field(
        default="OSV",
        description="Source of the CVE information"
    )


def cve_lookup_tool(cve_id: str) -> Dict[str, Any]:
    """
    Look up CVE information from OSV.dev and NVD databases.
    
    This tool queries multiple vulnerability databases to fetch detailed information
    about a specific CVE. It prioritizes OSV.dev and falls back to NVD if needed.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2022-40897")
    
    Returns:
        Dictionary containing structured CVE information.
    """
    
    # Normalize CVE ID (handle non-standard hyphens/dashes)
    cve_id = cve_id.strip().replace("‑", "-").replace("–", "-").replace("—", "-")
    
    # 1. Try OSV.dev (Primary)
    osv_result = _lookup_osv(cve_id)
    if osv_result["success"]:
        return osv_result
        
    # 2. Try NVD (Fallback)
    print(f"OSV.dev lookup failed for {cve_id}, trying NVD...")
    nvd_result = _lookup_nvd(cve_id)
    if nvd_result["success"]:
        return nvd_result
        
    # Return the error from the primary source if all fail, or a combined error
    return {
        "success": False,
        "error": f"CVE {cve_id} not found in any database (OSV, NVD)",
        "cve_id": cve_id,
        "summary": "Not found",
        "details": f"The CVE {cve_id} was not found in supported vulnerability databases.",
        "affected_packages": [],
        "vulnerable_methods": [],
        "severity": None,
        "cvss_score": None,
        "references": [],
        "source": "None"
    }


def _lookup_osv(cve_id: str) -> Dict[str, Any]:
    """Query OSV.dev API."""
    osv_api_url = "https://api.osv.dev/v1/vulns"
    
    try:
        response = requests.get(f"{osv_api_url}/{cve_id}", timeout=10)
        
        if response.status_code == 404:
            return {"success": False, "error": "Not found"}
            
        response.raise_for_status()
        data = response.json()
        
        # Extract affected packages
        affected_packages = []
        for affected in data.get("affected", []):
            package_info = {
                "package": affected.get("package", {}).get("name", "Unknown"),
                "ecosystem": affected.get("package", {}).get("ecosystem", "Unknown"),
                "ranges": []
            }
            for range_info in affected.get("ranges", []):
                package_info["ranges"].append({
                    "type": range_info.get("type", "SEMVER"),
                    "events": range_info.get("events", [])
                })
            if "versions" in affected:
                package_info["affected_versions"] = affected["versions"]
            affected_packages.append(package_info)
            
        # Extract vulnerable methods
        vulnerable_methods = []
        for affected in data.get("affected", []):
            db_specific = affected.get("database_specific", {})
            if "vulnerable_functions" in db_specific:
                vulnerable_methods.extend(db_specific["vulnerable_functions"])
            elif "functions" in db_specific:
                vulnerable_methods.extend(db_specific["functions"])
                
        # Extract severity
        severity = None
        cvss_score = None
        if "severity" in data and data["severity"]:
            severity_info = data["severity"][0]
            severity = severity_info.get("type", "UNKNOWN")
            try:
                val = severity_info.get("score")
                if isinstance(val, (int, float)):
                    cvss_score = float(val)
            except ValueError:
                pass

        references = [ref.get("url") for ref in data.get("references", []) if ref.get("url")]
        
        cve_info = CVEInfo(
            cve_id=cve_id,
            summary=data.get("summary", "No summary available"),
            details=data.get("details", data.get("summary", "No details available")),
            affected_packages=affected_packages,
            vulnerable_methods=list(set(vulnerable_methods)),
            severity=severity,
            cvss_score=cvss_score,
            references=references,
            published_date=data.get("published"),
            modified_date=data.get("modified"),
            source="OSV"
        )
        
        result = cve_info.model_dump()
        result["success"] = True
        return result
        
    except Exception as e:
        return {"success": False, "error": str(e)}


def _lookup_nvd(cve_id: str) -> Dict[str, Any]:
    """Query NVD API."""
    nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    try:
        response = requests.get(f"{nvd_api_url}?cveId={cve_id}", timeout=15)
        
        if response.status_code != 200:
            return {"success": False, "error": f"NVD API returned {response.status_code}"}
            
        data = response.json()
        if not data.get("vulnerabilities"):
            return {"success": False, "error": "Not found in NVD"}
            
        vuln = data["vulnerabilities"][0]["cve"]
        
        # Extract description
        descriptions = vuln.get("descriptions", [])
        summary = "No description available"
        for desc in descriptions:
            if desc.get("lang") == "en":
                summary = desc.get("value")
                break
                
        # Extract metrics (CVSS)
        cvss_score = None
        severity = None
        metrics = vuln.get("metrics", {})
        
        # Try CVSS v3.1, then v3.0, then v2.0
        cvss_data = None
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            
        if cvss_data:
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity")
            
        # Extract references
        references = [ref.get("url") for ref in vuln.get("references", []) if ref.get("url")]
        
        # NVD doesn't provide structured package info easily, so we leave it empty
        # The agent will rely on description or LLM for this
        
        cve_info = CVEInfo(
            cve_id=cve_id,
            summary=summary[:100] + "..." if len(summary) > 100 else summary,
            details=summary,
            affected_packages=[], # NVD parsing for CPEs is complex, skipping for now
            vulnerable_methods=[],
            severity=severity,
            cvss_score=cvss_score,
            references=references,
            published_date=vuln.get("published"),
            modified_date=vuln.get("lastModified"),
            source="NVD"
        )
        
        result = cve_info.model_dump()
        result["success"] = True
        return result
        
    except Exception as e:
        return {"success": False, "error": str(e)}


# Tool metadata for Google ADK
cve_lookup_tool.__annotations__["return"] = str
cve_lookup_tool.__doc__ = """
Look up CVE vulnerability information from OSV.dev and NVD databases.

Use this tool to fetch detailed information about a specific CVE identifier.
It checks OSV.dev first, then falls back to NVD.
Returns structured data including summary, affected packages, vulnerable methods,
severity ratings, and reference links.

Args:
    cve_id: CVE identifier in format CVE-YYYY-NNNNN (e.g., CVE-2022-40897)

Returns:
    Detailed CVE information including affected packages and vulnerable methods.
"""
