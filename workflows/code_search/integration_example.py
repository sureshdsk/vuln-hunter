"""Integration example for using code_search with vuln-hunter workflow."""

from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, asdict
import json

from .searcher import CodeSearcher
from .patterns import VulnerabilityPatterns


@dataclass
class VulnerabilityMatch:
    """Represents a vulnerability match in code."""

    file_path: str
    line_number: int
    column: int
    vulnerability_name: str
    severity: str
    cwe: str
    code_snippet: str
    description: str


class VulnHunterCodeAnalyzer:
    """Code analyzer integrated with vuln-hunter workflow."""

    def __init__(self):
        """Initialize the analyzer."""
        self.searcher = CodeSearcher()

    def analyze_repository(
        self,
        repo_path: Path,
        target_languages: List[str] = None,
        severity_filter: List[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze a repository for vulnerabilities.

        Args:
            repo_path: Path to the repository
            target_languages: List of languages to analyze (default: all)
            severity_filter: List of severity levels to include (default: all)

        Returns:
            Analysis results dictionary
        """
        if target_languages is None:
            target_languages = ['python', 'javascript', 'typescript']

        if severity_filter is None:
            severity_filter = ['critical', 'high', 'medium', 'low']

        results = {
            'repository': str(repo_path),
            'total_files_scanned': 0,
            'vulnerabilities': [],
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }

        # Get all patterns
        all_patterns = VulnerabilityPatterns.get_all_patterns()

        # Scan each language
        for language in target_languages:
            file_extensions = self._get_extensions_for_language(language)

            # Find all files for this language
            for ext in file_extensions:
                for file_path in repo_path.rglob(f'*{ext}'):
                    # Skip test files and dependencies
                    if self._should_skip_file(file_path):
                        continue

                    results['total_files_scanned'] += 1

                    # Scan with all patterns for this language
                    file_vulns = self._scan_file(file_path, language, all_patterns, severity_filter)
                    results['vulnerabilities'].extend(file_vulns)

                    # Update summary
                    for vuln in file_vulns:
                        results['summary'][vuln.severity] += 1

        return results

    def analyze_for_cve(
        self,
        repo_path: Path,
        cve_id: str,
        cve_description: str,
        affected_components: List[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze repository for a specific CVE.

        Args:
            repo_path: Path to the repository
            cve_id: CVE identifier (e.g., 'CVE-2024-1234')
            cve_description: Description of the CVE
            affected_components: List of affected libraries/components

        Returns:
            CVE-specific analysis results
        """
        results = {
            'cve_id': cve_id,
            'repository': str(repo_path),
            'affected_components': affected_components or [],
            'potential_vulnerabilities': [],
            'component_usage': []
        }

        # First, check if the repository uses affected components
        if affected_components:
            for component in affected_components:
                usage = self._find_component_usage(repo_path, component)
                results['component_usage'].extend(usage)

        # Run general vulnerability scan
        scan_results = self.analyze_repository(repo_path)
        results['potential_vulnerabilities'] = scan_results['vulnerabilities']
        results['summary'] = scan_results['summary']

        return results

    def _scan_file(
        self,
        file_path: Path,
        language: str,
        all_patterns: Dict[str, List],
        severity_filter: List[str]
    ) -> List[VulnerabilityMatch]:
        """Scan a single file with all applicable patterns."""
        vulnerabilities = []

        for category, pattern_list in all_patterns.items():
            for pattern in pattern_list:
                # Skip if wrong language
                if pattern.language != language:
                    continue

                # Skip if severity not in filter
                if pattern.severity not in severity_filter:
                    continue

                try:
                    results = self.searcher.search_pattern(
                        pattern.query,
                        file_path,
                        language
                    )

                    for result in results:
                        vuln = VulnerabilityMatch(
                            file_path=str(file_path),
                            line_number=result.line_number,
                            column=result.column,
                            vulnerability_name=pattern.name,
                            severity=pattern.severity,
                            cwe=pattern.cwe,
                            code_snippet=result.text[:200],  # Limit snippet length
                            description=pattern.description
                        )
                        vulnerabilities.append(vuln)

                except Exception as e:
                    # Pattern might not match - continue with others
                    pass

        return vulnerabilities

    def _find_component_usage(self, repo_path: Path, component: str) -> List[Dict]:
        """Find usage of a specific component/library."""
        usage = []

        # Search for imports in Python files
        for py_file in repo_path.rglob('*.py'):
            if self._should_skip_file(py_file):
                continue

            results = self.searcher.find_imports(py_file)

            for result in results:
                if component.lower() in result.text.lower():
                    usage.append({
                        'file': str(py_file),
                        'line': result.line_number,
                        'import_statement': result.text.strip()
                    })

        # Search for imports in JavaScript/TypeScript
        for js_file in list(repo_path.rglob('*.js')) + list(repo_path.rglob('*.ts')):
            if self._should_skip_file(js_file):
                continue

            results = self.searcher.find_imports(js_file)

            for result in results:
                if component.lower() in result.text.lower():
                    usage.append({
                        'file': str(js_file),
                        'line': result.line_number,
                        'import_statement': result.text.strip()
                    })

        return usage

    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if a file should be skipped during scanning."""
        skip_patterns = [
            'node_modules',
            '.venv',
            'venv',
            '__pycache__',
            '.git',
            'dist',
            'build',
            'test_',
            '_test.py',
            'tests/',
        ]

        path_str = str(file_path)
        return any(pattern in path_str for pattern in skip_patterns)

    def _get_extensions_for_language(self, language: str) -> List[str]:
        """Get file extensions for a programming language."""
        extension_map = {
            'python': ['.py'],
            'javascript': ['.js', '.jsx'],
            'typescript': ['.ts', '.tsx'],
            'java': ['.java'],
            'go': ['.go'],
            'rust': ['.rs'],
            'c': ['.c', '.h'],
            'cpp': ['.cpp', '.cc', '.cxx', '.hpp'],
        }
        return extension_map.get(language, [])

    def generate_report(self, analysis_results: Dict[str, Any], output_path: Path = None) -> str:
        """
        Generate a vulnerability report.

        Args:
            analysis_results: Results from analyze_repository or analyze_for_cve
            output_path: Optional path to save JSON report

        Returns:
            Report as formatted string
        """
        report_lines = []

        # Header
        report_lines.append("=" * 80)
        report_lines.append("VULNERABILITY ANALYSIS REPORT")
        report_lines.append("=" * 80)
        report_lines.append("")

        # Summary
        if 'cve_id' in analysis_results:
            report_lines.append(f"CVE: {analysis_results['cve_id']}")

        report_lines.append(f"Repository: {analysis_results['repository']}")
        report_lines.append(f"Files Scanned: {analysis_results.get('total_files_scanned', 'N/A')}")
        report_lines.append("")

        # Severity summary
        if 'summary' in analysis_results:
            report_lines.append("Vulnerability Summary:")
            summary = analysis_results['summary']
            report_lines.append(f"  Critical: {summary.get('critical', 0)}")
            report_lines.append(f"  High:     {summary.get('high', 0)}")
            report_lines.append(f"  Medium:   {summary.get('medium', 0)}")
            report_lines.append(f"  Low:      {summary.get('low', 0)}")
            report_lines.append("")

        # Component usage
        if 'component_usage' in analysis_results and analysis_results['component_usage']:
            report_lines.append("Affected Component Usage:")
            for usage in analysis_results['component_usage']:
                report_lines.append(f"  {usage['file']}:{usage['line']}")
                report_lines.append(f"    {usage['import_statement']}")
            report_lines.append("")

        # Vulnerabilities
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        if isinstance(vulnerabilities, list) and vulnerabilities:
            report_lines.append("Potential Vulnerabilities Found:")
            report_lines.append("-" * 80)

            # Group by severity
            for severity in ['critical', 'high', 'medium', 'low']:
                severity_vulns = [
                    v for v in vulnerabilities
                    if (isinstance(v, VulnerabilityMatch) and v.severity == severity)
                    or (isinstance(v, dict) and v.get('severity') == severity)
                ]

                if severity_vulns:
                    report_lines.append(f"\n{severity.upper()} Severity:")
                    report_lines.append("")

                    for vuln in severity_vulns:
                        if isinstance(vuln, VulnerabilityMatch):
                            vuln_dict = asdict(vuln)
                        else:
                            vuln_dict = vuln

                        report_lines.append(f"  [{vuln_dict['cwe']}] {vuln_dict['vulnerability_name']}")
                        report_lines.append(f"  File: {vuln_dict['file_path']}:{vuln_dict['line_number']}")
                        report_lines.append(f"  Description: {vuln_dict['description']}")
                        report_lines.append(f"  Code: {vuln_dict['code_snippet']}")
                        report_lines.append("")

        report_lines.append("=" * 80)

        report = "\n".join(report_lines)

        # Save JSON report if requested
        if output_path:
            # Convert VulnerabilityMatch objects to dicts for JSON serialization
            json_results = analysis_results.copy()
            if 'vulnerabilities' in json_results:
                json_results['vulnerabilities'] = [
                    asdict(v) if isinstance(v, VulnerabilityMatch) else v
                    for v in json_results['vulnerabilities']
                ]

            output_path.write_text(json.dumps(json_results, indent=2))

        return report


# Example usage
def main():
    """Example integration with vuln-hunter workflow."""
    analyzer = VulnHunterCodeAnalyzer()

    # Example 1: General repository scan
    print("Example 1: General Repository Scan")
    print("-" * 80)

    repo_path = Path(".")  # Current directory
    results = analyzer.analyze_repository(
        repo_path,
        target_languages=['python'],
        severity_filter=['critical', 'high']
    )

    report = analyzer.generate_report(results)
    print(report)

    # Example 2: CVE-specific analysis
    print("\n\nExample 2: CVE-Specific Analysis")
    print("-" * 80)

    cve_results = analyzer.analyze_for_cve(
        repo_path=repo_path,
        cve_id="CVE-2024-XXXX",
        cve_description="Example vulnerability",
        affected_components=['requests', 'urllib3']
    )

    cve_report = analyzer.generate_report(cve_results)
    print(cve_report)

    # Save JSON report
    output_path = Path("vulnerability_report.json")
    analyzer.generate_report(cve_results, output_path)
    print(f"\nJSON report saved to: {output_path}")


if __name__ == "__main__":
    main()
