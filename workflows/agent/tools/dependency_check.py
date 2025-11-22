"""
Dependency Check Tool for Google ADK Agent

This tool checks the repository's dependencies (requirements.txt, etc.)
against the affected packages listed in the CVE information.
"""

import re
from typing import Dict, Any, List, Optional
from packaging.version import parse as parse_version
from packaging.specifiers import SpecifierSet

def dependency_check_tool(
    code_index: Dict[str, Any],
    cve_info: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Check if the repository uses any vulnerable dependencies.
    
    Args:
        code_index: Code index containing file contents
        cve_info: CVE information containing affected packages
        
    Returns:
        Dictionary containing dependency findings
    """
    findings = []
    files_checked = 0
    
    try:
        files_data = code_index.get("files", {})
        affected_packages = cve_info.get("affected_packages", [])
        
        if not affected_packages:
            return {
                "success": True,
                "findings": [],
                "total_findings": 0
            }
            
        # Map package names to their affected info for quick lookup
        # Normalize package names to lowercase
        affected_map = {}
        for pkg in affected_packages:
            name = pkg.get("package", "").lower()
            if name:
                affected_map[name] = pkg
        
        # Iterate through files in the index
        for file_path, file_info in files_data.items():
            filename = file_path.split('/')[-1]
            
            # Check requirements.txt
            if filename == "requirements.txt":
                files_checked += 1
                content = file_info.get("content", "")
                findings.extend(_check_requirements_txt(file_path, content, affected_map))
                
            # Check pyproject.toml (basic support)
            elif filename == "pyproject.toml":
                files_checked += 1
                content = file_info.get("content", "")
                findings.extend(_check_pyproject_toml(file_path, content, affected_map))
                
            # Check Pipfile (basic support)
            elif filename == "Pipfile":
                files_checked += 1
                content = file_info.get("content", "")
                findings.extend(_check_pipfile(file_path, content, affected_map))
        
        return {
            "success": True,
            "findings": findings,
            "total_findings": len(findings),
            "files_checked": files_checked
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Error checking dependencies: {str(e)}",
            "findings": [],
            "total_findings": 0
        }

def _check_requirements_txt(file_path: str, content: str, affected_map: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse requirements.txt and check for vulnerable versions."""
    findings = []
    
    for line_num, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        # Parse requirement line (e.g., "django==1.8.1")
        # This is a simplified parser
        try:
            # Split by common operators
            parts = re.split(r'[=<>!~]+', line)
            if not parts:
                continue
                
            package_name = parts[0].strip().lower()
            
            if package_name in affected_map:
                # Found a potentially vulnerable package
                affected_info = affected_map[package_name]
                
                # Extract version if present
                # This is tricky without a full parser, but let's try to find the version part
                # Assuming "package==version" format for now which is common in requirements.txt
                version = None
                if "==" in line:
                    version = line.split("==")[1].split()[0].strip()
                
                if version:
                    is_vulnerable = _is_version_vulnerable(version, affected_info)
                    
                    if is_vulnerable:
                        findings.append({
                            "file_path": file_path,
                            "line_number": line_num,
                            "method_name": f"Dependency: {package_name}",
                            "code_snippet": line,
                            "exploitable": True,
                            "confidence": 1.0,
                            "explanation": f"Vulnerable version of {package_name} ({version}) detected. Affected versions: {affected_info.get('ranges', [])}"
                        })
        except Exception:
            continue
            
    return findings

def _check_pyproject_toml(file_path: str, content: str, affected_map: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Basic check for pyproject.toml."""
    # TODO: Implement proper TOML parsing
    # For now, just regex search for "package = version"
    findings = []
    return findings

def _check_pipfile(file_path: str, content: str, affected_map: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Basic check for Pipfile."""
    # TODO: Implement proper Pipfile parsing
    findings = []
    return findings

def _is_version_vulnerable(version: str, affected_info: Dict[str, Any]) -> bool:
    """Check if a version string matches the affected ranges."""
    try:
        v = parse_version(version)
        
        ranges = affected_info.get("ranges", [])
        for r in ranges:
            events = r.get("events", [])
            
            # Build a specifier set from events
            # OSV events are like: {"introduced": "0"}, {"fixed": "1.2.3"}
            specifiers = []
            
            introduced = None
            fixed = None
            
            for event in events:
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
            
            # Check if version is within this range
            # [introduced, fixed)
            
            if introduced and introduced != "0":
                if v < parse_version(introduced):
                    continue # Too old
            
            if fixed:
                if v >= parse_version(fixed):
                    continue # Fixed
            
            # If we got here, it's in the range
            return True
            
        return False
        
    except Exception:
        # If version parsing fails, assume potential vulnerability but maybe lower confidence?
        # For safety, let's return False to avoid noise, or True to be safe?
        # Let's return False for now to avoid crashes
        return False
