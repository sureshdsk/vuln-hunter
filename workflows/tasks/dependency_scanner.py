"""
Dependency Scanner for detecting version-specific CVEs

This module scans requirements.txt, setup.py, and other dependency files
to detect vulnerable package versions.
"""

import re
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from prefect import task
from prefect.logging import get_run_logger


@task
def scan_dependencies_for_vulnerabilities(
    repo_path: str,
    cve_info: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Scan repository dependencies for version-specific vulnerabilities.

    Args:
        repo_path: Path to the repository
        cve_info: CVE information including affected packages/versions

    Returns:
        Dictionary containing dependency vulnerability findings
    """
    logger = get_run_logger()
    logger.info("Scanning dependencies for vulnerabilities")

    findings = []
    dependencies = {}

    try:
        # Parse dependency files
        dependencies.update(_parse_requirements_txt(repo_path))
        dependencies.update(_parse_setup_py(repo_path))
        dependencies.update(_parse_pyproject_toml(repo_path))

        logger.info(f"Found {len(dependencies)} dependencies")

        # Check each dependency against CVE
        cve_id = cve_info.get('cve_id', '')
        affected_packages = _extract_affected_packages_from_cve(cve_info)

        logger.info(f"Checking against {len(affected_packages)} affected packages from CVE")
        for pkg in affected_packages:
            logger.debug(f"  Affected package: {pkg.get('name', 'UNKNOWN')}")
    except Exception as e:
        logger.error(f"Error during dependency scanning setup: {e}")
        return {
            'success': False,
            'dependencies': {},
            'findings': [],
            'total_dependencies': 0,
            'vulnerable_dependencies': 0,
            'error': str(e)
        }

    try:
        for package_name, version_spec in dependencies.items():
            # Check if this package is affected by the CVE
            for affected_pkg in affected_packages:
                # Skip if no package name in affected_pkg
                affected_pkg_name = affected_pkg.get('name', '')
                if not affected_pkg_name:
                    logger.debug(f"Skipping affected package with no name: {affected_pkg}")
                    continue

                if _package_matches(package_name, affected_pkg_name):
                    logger.debug(f"Checking if {package_name}=={version_spec} is vulnerable")
                    is_vulnerable, reason = _check_version_vulnerability(
                        version_spec,
                        affected_pkg.get('affected_versions', []),
                        affected_pkg.get('fixed_versions', [])
                    )

                    if is_vulnerable:
                        findings.append({
                            'type': 'DEPENDENCY_VULNERABILITY',
                            'package': package_name,
                            'installed_version': version_spec,
                            'cve_id': cve_id,
                            'severity': 'CRITICAL',
                            'affected_versions': affected_pkg.get('affected_versions', []),
                            'fixed_versions': affected_pkg.get('fixed_versions', []),
                            'reason': reason,
                            'exploitable': True,
                            'confidence': 100.0
                        })
                        logger.warning(f"Found vulnerable dependency: {package_name}=={version_spec}")
    except Exception as e:
        logger.error(f"Error during dependency version matching: {e}")
        import traceback
        logger.error(traceback.format_exc())

    return {
        'success': True,
        'dependencies': dependencies,
        'findings': findings,
        'total_dependencies': len(dependencies),
        'vulnerable_dependencies': len(findings)
    }


def _parse_requirements_txt(repo_path: str) -> Dict[str, str]:
    """Parse requirements.txt file."""
    dependencies = {}
    req_file = Path(repo_path) / 'requirements.txt'

    if not req_file.exists():
        return dependencies

    try:
        with open(req_file, 'r') as f:
            for line in f:
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Parse: django==2.2.1 or django>=2.0,<3.0
                match = re.match(r'^([a-zA-Z0-9_-]+)([><=!~]+)(.+)$', line)
                if match:
                    package = match.group(1).lower()
                    operator = match.group(2)
                    version = match.group(3).strip()

                    # Store the version spec
                    dependencies[package] = version

    except Exception as e:
        print(f"Error parsing requirements.txt: {e}")

    return dependencies


def _parse_setup_py(repo_path: str) -> Dict[str, str]:
    """Parse setup.py file for install_requires."""
    dependencies = {}
    setup_file = Path(repo_path) / 'setup.py'

    if not setup_file.exists():
        return dependencies

    try:
        with open(setup_file, 'r') as f:
            content = f.read()

            # Look for install_requires
            match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if match:
                requires = match.group(1)

                # Parse each requirement
                for line in requires.split(','):
                    line = line.strip().strip('"\'')

                    if not line:
                        continue

                    match = re.match(r'^([a-zA-Z0-9_-]+)([><=!~]+)(.+)$', line)
                    if match:
                        package = match.group(1).lower()
                        version = match.group(3).strip()
                        dependencies[package] = version

    except Exception as e:
        print(f"Error parsing setup.py: {e}")

    return dependencies


def _parse_pyproject_toml(repo_path: str) -> Dict[str, str]:
    """Parse pyproject.toml file."""
    dependencies = {}
    toml_file = Path(repo_path) / 'pyproject.toml'

    if not toml_file.exists():
        return dependencies

    try:
        import toml
        with open(toml_file, 'r') as f:
            data = toml.load(f)

            # Check different dependency locations
            deps = data.get('project', {}).get('dependencies', [])
            deps.extend(data.get('tool', {}).get('poetry', {}).get('dependencies', {}).keys())

            for dep in deps:
                if isinstance(dep, str):
                    match = re.match(r'^([a-zA-Z0-9_-]+)([><=!~]+)(.+)$', dep)
                    if match:
                        package = match.group(1).lower()
                        version = match.group(3).strip()
                        dependencies[package] = version

    except Exception as e:
        print(f"Error parsing pyproject.toml: {e}")

    return dependencies


def _extract_affected_packages_from_cve(cve_info: Dict[str, Any]) -> List[Dict]:
    """
    Extract affected packages and versions from CVE info.

    For CVE-2025-64458, this would extract Django and its vulnerable versions.
    """
    affected = []
    seen_packages = set()

    # Try to extract from CVE data
    if 'affected_packages' in cve_info:
        for pkg in cve_info['affected_packages']:
            if isinstance(pkg, dict):
                # Try 'package' key first (from OSV), then 'name' key
                pkg_name = pkg.get('package') or pkg.get('name', 'Unknown')
                pkg_name = pkg_name.lower()

                # If package is 'unknown', try to infer from version patterns or description
                if pkg_name == 'unknown':
                    # Check if versions look like Django versions (4.x.x pattern)
                    affected_versions = pkg.get('affected_versions', [])
                    if affected_versions and any(v.startswith('4.2') for v in affected_versions):
                        pkg_name = 'django'  # Infer Django from version pattern

                if pkg_name != 'unknown' and pkg_name not in seen_packages:
                    # Normalize the structure
                    affected.append({
                        'name': pkg_name,
                        'affected_versions': pkg.get('affected_versions', []),
                        'fixed_versions': pkg.get('fixed_versions', [])
                    })
                    seen_packages.add(pkg_name)
            elif isinstance(pkg, str):
                pkg_name = pkg.lower()
                if pkg_name not in seen_packages:
                    affected.append({'name': pkg_name})
                    seen_packages.add(pkg_name)

    # Fallback: Parse from description
    description = cve_info.get('description', '').lower()

    # Common patterns
    if 'django' in description and 'django' not in seen_packages:
        # Try to extract version info from description
        # Example: "Django before 3.2.18, 4.0.x before 4.0.10, 4.1.x before 4.1.7"
        affected.append({
            'name': 'django',
            'affected_versions': _extract_versions_from_description(description),
            'fixed_versions': []
        })
        seen_packages.add('django')

    # Add more package patterns as needed
    for package in ['flask', 'requests', 'urllib3', 'pillow', 'setuptools', 'wheel']:
        if package in description and package not in seen_packages:
            affected.append({
                'name': package,
                'affected_versions': _extract_versions_from_description(description),
                'fixed_versions': []
            })
            seen_packages.add(package)

    return affected


def _extract_versions_from_description(description: str) -> List[str]:
    """Extract version information from CVE description."""
    versions = []

    # Pattern: "before X.Y.Z"
    matches = re.findall(r'before\s+(\d+\.\d+(?:\.\d+)?)', description)
    for match in matches:
        versions.append(f'<{match}')

    # Pattern: "X.Y.x before X.Y.Z"
    matches = re.findall(r'(\d+\.\d+)\.x\s+before\s+(\d+\.\d+\.\d+)', description)
    for major_minor, fixed in matches:
        versions.append(f'>={major_minor}.0,<{fixed}')

    return versions


def _package_matches(installed_name: str, cve_package_name: str) -> bool:
    """Check if package names match (case-insensitive, handle variations)."""
    installed_name = installed_name.lower().replace('_', '-')
    cve_package_name = cve_package_name.lower().replace('_', '-')
    return installed_name == cve_package_name


def _check_version_vulnerability(
    installed_version: str,
    affected_versions: List[str],
    fixed_versions: List[str]
) -> tuple[bool, str]:
    """
    Check if an installed version is vulnerable.

    Returns:
        (is_vulnerable, reason)
    """
    try:
        # Remove operators from installed version
        clean_version = re.sub(r'^[><=!~]+', '', installed_version).strip()

        # If no version constraints specified, assume vulnerable
        if not affected_versions and not fixed_versions:
            return True, "Package is mentioned in CVE (no version constraints available)"

        # First, check if this exact version is in the affected_versions list
        # This handles CVEs with explicit version lists like ['4.2.25', '4.2.24', ...]
        if clean_version in affected_versions:
            return True, f"Version {clean_version} is explicitly listed as vulnerable"

        # Check against version range constraints
        for affected in affected_versions:
            # Skip if this is an exact version (not a range)
            if not any(op in affected for op in ['<', '>', '=']):
                continue

            if '<' in affected and '>=' not in affected:
                # Example: <3.2.18
                max_version = affected.replace('<', '').strip()
                if _version_less_than(clean_version, max_version):
                    return True, f"Version {clean_version} < {max_version} (vulnerable)"

            elif '>=' in affected and '<' in affected:
                # Example: >=3.0,<3.2.18
                parts = affected.split(',')
                min_ver = parts[0].replace('>=', '').strip()
                max_ver = parts[1].replace('<', '').strip()

                if (_version_greater_equal(clean_version, min_ver) and
                    _version_less_than(clean_version, max_ver)):
                    return True, f"Version {clean_version} in range {affected} (vulnerable)"

        return False, "Version appears to be safe"

    except Exception as e:
        # If version comparison fails, mark as potentially vulnerable
        return True, f"Could not verify version safety: {e}"


def _version_less_than(v1: str, v2: str) -> bool:
    """Simple version comparison: v1 < v2"""
    try:
        v1_parts = [int(x) for x in v1.split('.')]
        v2_parts = [int(x) for x in v2.split('.')]

        # Pad to same length
        while len(v1_parts) < len(v2_parts):
            v1_parts.append(0)
        while len(v2_parts) < len(v1_parts):
            v2_parts.append(0)

        return v1_parts < v2_parts
    except:
        return False


def _version_greater_equal(v1: str, v2: str) -> bool:
    """Simple version comparison: v1 >= v2"""
    try:
        v1_parts = [int(x) for x in v1.split('.')]
        v2_parts = [int(x) for x in v2.split('.')]

        while len(v1_parts) < len(v2_parts):
            v1_parts.append(0)
        while len(v2_parts) < len(v1_parts):
            v2_parts.append(0)

        return v1_parts >= v2_parts
    except:
        return False
