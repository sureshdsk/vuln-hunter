"""
Enhanced Code Analysis Tasks

Additional tasks that leverage the Tree-sitter enhanced code index
for deeper vulnerability analysis.
"""

from typing import Dict, Any, List
from pathlib import Path
from prefect import task
from prefect.logging import get_run_logger

try:
    from code_search.integration_example import VulnHunterCodeAnalyzer
    ANALYZER_AVAILABLE = True
except ImportError:
    ANALYZER_AVAILABLE = False
    VulnHunterCodeAnalyzer = None


@task
def analyze_with_tree_sitter(
    repo_path: str,
    cve_info: Dict[str, Any],
    code_index: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Perform deep vulnerability analysis using Tree-sitter code search.

    This task complements the AI agent analysis by providing structured
    vulnerability detection using Tree-sitter patterns.

    Args:
        repo_path: Path to the repository
        cve_info: CVE information dictionary
        code_index: Enhanced code index from build_code_index

    Returns:
        Dictionary containing:
        - tree_sitter_findings: Structured vulnerability findings
        - affected_files: List of files with potential issues
        - severity_distribution: Count by severity level
        - recommendations: Specific remediation suggestions
    """
    logger = get_run_logger()
    logger.info("Running Tree-sitter deep analysis")

    if not ANALYZER_AVAILABLE:
        logger.warning("VulnHunterCodeAnalyzer not available, skipping Tree-sitter analysis")
        return {
            "success": False,
            "error": "Tree-sitter analyzer not available",
            "tree_sitter_findings": []
        }

    try:
        analyzer = VulnHunterCodeAnalyzer()

        # Extract affected components from CVE info
        affected_components = _extract_affected_components(cve_info)

        # Perform CVE-specific analysis
        results = analyzer.analyze_for_cve(
            repo_path=Path(repo_path),
            cve_id=cve_info.get('cve_id', 'UNKNOWN'),
            cve_description=cve_info.get('description', ''),
            affected_components=affected_components
        )

        # Enrich with pre-scan results from code index
        if code_index.get('vulnerabilities', {}).get('pre_scan_results'):
            results['pre_scan_results'] = code_index['vulnerabilities']['pre_scan_results']

        # Generate structured output
        analysis = {
            "success": True,
            "tree_sitter_findings": results.get('potential_vulnerabilities', []),
            "component_usage": results.get('component_usage', []),
            "affected_files": _extract_affected_files(results),
            "severity_distribution": results.get('summary', {}),
            "total_findings": len(results.get('potential_vulnerabilities', [])),
            "pre_scan_findings": len(code_index.get('vulnerabilities', {}).get('pre_scan_results', [])),
            "recommendations": _generate_recommendations(results, cve_info)
        }

        logger.info(f"Tree-sitter analysis complete: {analysis['total_findings']} findings")

        return analysis

    except Exception as e:
        logger.error(f"Error in Tree-sitter analysis: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "tree_sitter_findings": []
        }


@task
def enrich_code_index_with_cve_context(
    code_index: Dict[str, Any],
    cve_info: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Enrich the code index with CVE-specific context.

    This task adds CVE-specific information to the code index to help
    the AI agent focus on relevant code patterns.

    Args:
        code_index: Enhanced code index
        cve_info: CVE information

    Returns:
        Enriched code index with CVE context
    """
    logger = get_run_logger()
    logger.info("Enriching code index with CVE context")

    enriched_index = code_index.copy()

    # Add CVE context
    enriched_index['cve_context'] = {
        'cve_id': cve_info.get('cve_id'),
        'description': cve_info.get('description'),
        'severity': cve_info.get('severity'),
        'affected_packages': _extract_affected_components(cve_info),
        'vulnerability_type': _classify_vulnerability_type(cve_info)
    }

    # Find relevant files based on CVE context
    relevant_files = _find_relevant_files(code_index, cve_info)
    enriched_index['cve_context']['relevant_files'] = relevant_files

    # Highlight suspicious patterns
    suspicious_patterns = _find_suspicious_patterns(code_index, cve_info)
    enriched_index['cve_context']['suspicious_patterns'] = suspicious_patterns

    logger.info(f"Found {len(relevant_files)} relevant files for CVE analysis")

    return enriched_index


def _extract_affected_components(cve_info: Dict[str, Any]) -> List[str]:
    """Extract affected components/packages from CVE info."""
    components = []

    # Try to extract from various fields
    if 'affected_packages' in cve_info:
        packages = cve_info['affected_packages']
        if isinstance(packages, list):
            for pkg in packages:
                # Handle both string and dict formats
                if isinstance(pkg, str):
                    components.append(pkg)
                elif isinstance(pkg, dict):
                    # Try to extract package name from dict
                    if 'name' in pkg:
                        components.append(pkg['name'])
                    elif 'package' in pkg:
                        components.append(pkg['package'])

    if 'references' in cve_info:
        # Parse references for package names
        refs = cve_info['references']
        if isinstance(refs, list):
            for ref in refs:
                if isinstance(ref, dict) and 'package' in ref:
                    components.append(ref['package'])
                elif isinstance(ref, str):
                    components.append(ref)

    # Extract from description using common patterns
    description = cve_info.get('description', '').lower()
    common_packages = [
        'django', 'flask', 'requests', 'urllib3', 'pillow',
        'numpy', 'pandas', 'tensorflow', 'pytorch', 'lxml'
    ]

    for package in common_packages:
        if package in description:
            components.append(package)

    # Deduplicate - only string values
    unique_components = []
    seen = set()
    for comp in components:
        if isinstance(comp, str) and comp not in seen:
            unique_components.append(comp)
            seen.add(comp)

    return unique_components


def _classify_vulnerability_type(cve_info: Dict[str, Any]) -> str:
    """Classify the type of vulnerability from CVE info."""
    description = cve_info.get('description', '').lower()

    vulnerability_types = {
        'sql injection': ['sql injection', 'sql query', 'database query'],
        'xss': ['cross-site scripting', 'xss', 'script injection'],
        'command injection': ['command injection', 'shell injection', 'code execution'],
        'path traversal': ['path traversal', 'directory traversal', '../'],
        'deserialization': ['deserialization', 'pickle', 'unmarshall'],
        'xxe': ['xxe', 'xml external entity', 'xml parser'],
        'csrf': ['csrf', 'cross-site request forgery'],
        'authentication': ['authentication bypass', 'auth bypass'],
        'authorization': ['privilege escalation', 'authorization'],
        'cryptography': ['weak encryption', 'cryptography', 'hashing']
    }

    for vuln_type, keywords in vulnerability_types.items():
        if any(keyword in description for keyword in keywords):
            return vuln_type

    return 'unknown'


def _find_relevant_files(code_index: Dict[str, Any], cve_info: Dict[str, Any]) -> List[str]:
    """Find files relevant to the CVE based on imports and content."""
    relevant_files = []

    affected_components = _extract_affected_components(cve_info)
    vuln_type = _classify_vulnerability_type(cve_info)

    for file_path, file_info in code_index.get('files', {}).items():
        relevance_score = 0

        # Check imports
        for imp in file_info.get('imports', []):
            if any(comp in imp.lower() for comp in affected_components):
                relevance_score += 10

        # Check for vulnerability-related patterns in the file
        content = file_info.get('content', '').lower()

        if vuln_type == 'sql injection':
            if 'execute' in content or 'cursor' in content:
                relevance_score += 5

        elif vuln_type == 'xss':
            if 'render' in content or 'template' in content:
                relevance_score += 5

        elif vuln_type == 'command injection':
            if 'subprocess' in content or 'os.system' in content:
                relevance_score += 5

        # Files with any relevance are considered
        if relevance_score > 0:
            relevant_files.append({
                'file': file_path,
                'relevance_score': relevance_score
            })

    # Sort by relevance
    relevant_files.sort(key=lambda x: x['relevance_score'], reverse=True)

    return relevant_files[:20]  # Top 20 most relevant files


def _find_suspicious_patterns(code_index: Dict[str, Any], cve_info: Dict[str, Any]) -> List[Dict]:
    """Find suspicious code patterns related to the CVE."""
    suspicious = []

    # Check pre-scan results
    pre_scan = code_index.get('vulnerabilities', {}).get('pre_scan_results', [])

    vuln_type = _classify_vulnerability_type(cve_info)

    # Filter pre-scan results by vulnerability type
    type_mapping = {
        'sql injection': 'SQL Injection',
        'xss': 'XSS',
        'command injection': 'Command Injection',
        'path traversal': 'Path Traversal',
        'deserialization': 'Deserialization'
    }

    target_pattern = type_mapping.get(vuln_type)

    for result in pre_scan:
        if target_pattern and target_pattern.lower() in result.get('pattern_name', '').lower():
            suspicious.append(result)

    return suspicious


def _extract_affected_files(analysis_results: Dict[str, Any]) -> List[str]:
    """Extract unique list of affected files from analysis results."""
    files = set()

    for vuln in analysis_results.get('potential_vulnerabilities', []):
        if isinstance(vuln, dict) and 'file_path' in vuln:
            files.add(vuln['file_path'])
        elif isinstance(vuln, dict) and 'file' in vuln:
            files.add(vuln['file'])

    for usage in analysis_results.get('component_usage', []):
        if 'file' in usage:
            files.add(usage['file'])

    return sorted(list(files))


def _generate_recommendations(
    analysis_results: Dict[str, Any],
    cve_info: Dict[str, Any]
) -> List[str]:
    """Generate specific remediation recommendations."""
    recommendations = []

    vuln_type = _classify_vulnerability_type(cve_info)

    # General recommendation
    recommendations.append(
        f"Review all instances of {vuln_type} vulnerabilities found in the codebase"
    )

    # Component-specific recommendations
    if analysis_results.get('component_usage'):
        affected_components = set()
        for usage in analysis_results['component_usage']:
            if 'import_statement' in usage:
                affected_components.add(usage['import_statement'].split()[1])

        if affected_components:
            recommendations.append(
                f"Update affected packages: {', '.join(affected_components)}"
            )

    # Severity-based recommendations
    summary = analysis_results.get('summary', {})
    critical_count = summary.get('critical', 0)
    high_count = summary.get('high', 0)

    if critical_count > 0:
        recommendations.append(
            f"URGENT: Address {critical_count} critical severity findings immediately"
        )

    if high_count > 0:
        recommendations.append(
            f"Prioritize fixing {high_count} high severity findings"
        )

    # Type-specific recommendations
    type_recommendations = {
        'sql injection': 'Use parameterized queries or ORM methods instead of string concatenation',
        'xss': 'Implement proper output encoding and Content Security Policy',
        'command injection': 'Avoid shell=True and use subprocess with argument lists',
        'path traversal': 'Validate and sanitize file paths, use os.path.abspath',
        'deserialization': 'Avoid pickle with untrusted data, use JSON instead'
    }

    if vuln_type in type_recommendations:
        recommendations.append(type_recommendations[vuln_type])

    return recommendations
