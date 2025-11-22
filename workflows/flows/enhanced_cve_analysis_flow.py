"""
Enhanced Prefect workflow for CVE analysis with Tree-sitter integration
"""

from prefect import flow
from prefect.logging import get_run_logger

# Import tasks
from tasks.vuln_db_tasks import fetch_cve_data
from tasks.repo_tasks import clone_repository, cleanup_repository
from tasks.indexer_tasks import build_code_index
from tasks.enhanced_indexer_tasks import (
    analyze_with_tree_sitter,
    enrich_code_index_with_cve_context
)
from tasks.agent_tasks import run_ai_agent
from tasks.dependency_scanner import scan_dependencies_for_vulnerabilities


@flow(name="Enhanced CVE Analysis Flow")
def enhanced_analyze_repository_for_cve(
    job_id: str,
    repo_url: str,
    branch: str,
    cve_id: str,
    use_tree_sitter: bool = True,
    scan_vulnerabilities: bool = True
):
    """
    Enhanced CVE analysis workflow with Tree-sitter integration.

    This flow combines:
    1. Tree-sitter semantic code analysis
    2. Vulnerability pattern pre-scanning
    3. AI agent analysis with enriched context
    4. Comprehensive reporting

    Args:
        job_id: UUID of the analysis job
        repo_url: GitHub repository URL
        branch: Branch to analyze
        cve_id: CVE identifier
        use_tree_sitter: Enable Tree-sitter analysis (default: True)
        scan_vulnerabilities: Enable vulnerability pre-scanning (default: True)
    """
    logger = get_run_logger()
    logger.info(f"Starting Enhanced CVE analysis for job {job_id}")
    logger.info(f"Repository: {repo_url}, Branch: {branch}, CVE: {cve_id}")
    logger.info(f"Tree-sitter: {use_tree_sitter}, Pre-scan: {scan_vulnerabilities}")

    repo_path = None

    try:
        # ============================================================
        # Phase 1: Data Collection
        # ============================================================
        logger.info("Phase 1: Fetching CVE data...")

        # 1. Fetch CVE data
        cve_info = fetch_cve_data(cve_id)

        if not cve_info.get("success"):
            logger.error(f"Aborting analysis: {cve_info.get('error')}")
            return {
                "job_id": job_id,
                "status": "ERROR",
                "error": cve_info.get("error"),
                "phase": "cve_fetch"
            }

        # 2. Clone repository
        logger.info("Phase 1: Cloning repository...")
        repo_path = clone_repository(repo_url, branch)

        # ============================================================
        # Phase 2: Code Indexing & Pre-scanning
        # ============================================================
        logger.info("Phase 2: Building enhanced code index...")

        # 3. Build enhanced code index with Tree-sitter
        code_index = build_code_index(
            repo_path,
            use_tree_sitter=use_tree_sitter,
            scan_vulnerabilities=scan_vulnerabilities
        )

        # Log indexing statistics
        stats = code_index.get('statistics', {})
        logger.info(f"Indexed {stats.get('total_files', 0)} files")
        logger.info(f"Total lines: {stats.get('total_lines', 0)}")
        logger.info(f"Languages: {stats.get('languages', {})}")

        vuln_stats = code_index.get('vulnerabilities', {})
        if scan_vulnerabilities:
            logger.info(
                f"Pre-scan: {len(vuln_stats.get('pre_scan_results', []))} "
                f"potential vulnerabilities found"
            )

        # 4. Scan dependencies for version-specific vulnerabilities
        logger.info("Phase 2: Scanning dependencies for vulnerabilities...")
        dependency_scan = scan_dependencies_for_vulnerabilities(repo_path, cve_info)

        logger.info(f"Total dependencies: {dependency_scan.get('total_dependencies', 0)}")
        logger.info(f"Vulnerable dependencies: {dependency_scan.get('vulnerable_dependencies', 0)}")

        # 5. Enrich code index with CVE context
        logger.info("Phase 2: Enriching code index with CVE context...")
        enriched_index = enrich_code_index_with_cve_context(code_index, cve_info)

        cve_context = enriched_index.get('cve_context', {})
        logger.info(f"CVE Type: {cve_context.get('vulnerability_type')}")
        logger.info(f"Relevant files: {len(cve_context.get('relevant_files', []))}")

        # ============================================================
        # Phase 3: Deep Analysis
        # ============================================================
        logger.info("Phase 3: Running deep vulnerability analysis...")

        # 5. Tree-sitter deep analysis (parallel with AI agent)
        tree_sitter_analysis = None
        if use_tree_sitter:
            logger.info("Phase 3a: Running Tree-sitter analysis...")
            tree_sitter_analysis = analyze_with_tree_sitter(
                repo_path,
                cve_info,
                enriched_index
            )

            if tree_sitter_analysis.get('success'):
                logger.info(
                    f"Tree-sitter found {tree_sitter_analysis.get('total_findings', 0)} "
                    f"vulnerability patterns"
                )

        # 6. Run AI agent analysis
        logger.info("Phase 3b: Running AI agent analysis...")
        ai_analysis = run_ai_agent(
            cve_info=cve_info,
            code_index=enriched_index,
            job_id=job_id,
            repo_url=repo_url,
            branch=branch
        )

        # ============================================================
        # Phase 4: Report Generation & Synthesis
        # ============================================================
        logger.info("Phase 4: Generating comprehensive report...")

        # 7. Synthesize results from all sources
        final_report = _synthesize_results(
            job_id=job_id,
            cve_info=cve_info,
            code_index=enriched_index,
            tree_sitter_analysis=tree_sitter_analysis,
            ai_analysis=ai_analysis,
            dependency_scan=dependency_scan,
            repo_url=repo_url,
            branch=branch
        )

        logger.info(f"Completed Enhanced CVE analysis for job {job_id}")
        logger.info(f"Final status: {final_report.get('status', 'UNKNOWN')}")
        logger.info(
            f"Total findings: {final_report.get('summary', {}).get('total_findings', 0)}"
        )

        return final_report

    except Exception as e:
        logger.error(f"Error in Enhanced CVE analysis workflow: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())

        # Return error report structure
        return {
            "job_id": job_id,
            "status": "ERROR",
            "error": str(e),
            "phase": "unknown"
        }

    finally:
        # ============================================================
        # Phase 5: Cleanup
        # ============================================================
        if repo_path:
            logger.info("Phase 5: Cleaning up repository...")
            cleanup_repository(repo_path)


def _synthesize_results(
    job_id: str,
    cve_info: dict,
    code_index: dict,
    tree_sitter_analysis: dict,
    ai_analysis: dict,
    dependency_scan: dict,
    repo_url: str,
    branch: str
) -> dict:
    """
    Synthesize results from multiple analysis sources into a comprehensive report.
    """
    # Determine overall status
    if ai_analysis.get('status') == 'ERROR':
        status = 'ERROR'
    elif tree_sitter_analysis and not tree_sitter_analysis.get('success'):
        status = 'PARTIAL'
    elif dependency_scan and dependency_scan.get('vulnerable_dependencies', 0) > 0:
        # If vulnerable dependencies found, override status to VULNERABLE
        status = 'VULNERABLE'
    else:
        status = ai_analysis.get('status', 'UNKNOWN')

    # Combine findings from all sources
    all_findings = []

    # AI agent findings
    if ai_analysis.get('findings'):
        all_findings.extend(ai_analysis['findings'])

    # Tree-sitter findings
    if tree_sitter_analysis and tree_sitter_analysis.get('tree_sitter_findings'):
        # Convert Tree-sitter findings to common format
        for finding in tree_sitter_analysis['tree_sitter_findings']:
            all_findings.append({
                'source': 'tree-sitter',
                'type': finding.get('pattern_name', 'Unknown'),
                'severity': finding.get('severity', 'medium'),
                'file': finding.get('file', finding.get('file_path', 'Unknown')),
                'line': finding.get('line', 0),
                'description': finding.get('description', ''),
                'cwe': finding.get('cwe', '')
            })

    # Dependency scan findings
    if dependency_scan and dependency_scan.get('findings'):
        for dep_finding in dependency_scan['findings']:
            all_findings.append({
                'source': 'dependency-scan',
                'type': dep_finding.get('type', 'DEPENDENCY_VULNERABILITY'),
                'severity': dep_finding.get('severity', 'critical').lower(),
                'file': 'requirements.txt',
                'line': 0,
                'description': (
                    f"Vulnerable dependency: {dep_finding.get('package')} "
                    f"{dep_finding.get('installed_version')} - {dep_finding.get('reason', 'Version matches CVE')}"
                ),
                'cwe': 'Dependency Vulnerability',
                'package': dep_finding.get('package'),
                'version': dep_finding.get('installed_version'),
                'cve_id': dep_finding.get('cve_id'),
                'affected_versions': dep_finding.get('affected_versions', []),
                'fixed_versions': dep_finding.get('fixed_versions', []),
                'exploitable': dep_finding.get('exploitable', True),
                'confidence': dep_finding.get('confidence', 100.0)
            })

    # Calculate summary statistics
    summary = {
        'total_findings': len(all_findings),
        'critical_findings': sum(1 for f in all_findings if f.get('severity') == 'critical'),
        'high_findings': sum(1 for f in all_findings if f.get('severity') == 'high'),
        'medium_findings': sum(1 for f in all_findings if f.get('severity') == 'medium'),
        'low_findings': sum(1 for f in all_findings if f.get('severity') == 'low'),
        'ai_findings': ai_analysis.get('total_findings', 0),
        'tree_sitter_findings': tree_sitter_analysis.get('total_findings', 0) if tree_sitter_analysis else 0,
        'pre_scan_findings': len(code_index.get('vulnerabilities', {}).get('pre_scan_results', [])),
        'dependency_findings': len(dependency_scan.get('findings', [])) if dependency_scan else 0
    }

    # Build comprehensive report
    from datetime import datetime

    report = {
        # Job metadata
        'job_id': job_id,
        'status': status,
        'cve_id': cve_info.get('cve_id'),
        'repository': repo_url,
        'repository_url': repo_url,  # For report_builder compatibility
        'branch': branch,
        'timestamp': datetime.now().isoformat(),

        # CVE info for report_builder
        'cve_summary': cve_info.get('description', 'N/A'),
        'cve_severity': cve_info.get('severity', 'N/A'),
        'cve_score': cve_info.get('cvss_score', 'N/A'),

        # Analysis results
        'findings': all_findings,
        'summary': summary,
        'total_findings': len(all_findings),
        'exploitable_findings': ai_analysis.get('exploitable_findings', 0),
        'files_analyzed': code_index.get('statistics', {}).get('total_files', 0),

        # Detailed breakdowns
        'ai_analysis': {
            'status': ai_analysis.get('status'),
            'findings_count': ai_analysis.get('total_findings', 0),
            'exploitable_count': ai_analysis.get('exploitable_findings', 0),
            'confidence': ai_analysis.get('confidence', 'unknown')
        },

        'tree_sitter_analysis': {
            'enabled': tree_sitter_analysis is not None,
            'success': tree_sitter_analysis.get('success', False) if tree_sitter_analysis else False,
            'findings_count': tree_sitter_analysis.get('total_findings', 0) if tree_sitter_analysis else 0,
            'severity_distribution': tree_sitter_analysis.get('severity_distribution', {}) if tree_sitter_analysis else {},
            'affected_files': tree_sitter_analysis.get('affected_files', []) if tree_sitter_analysis else []
        } if tree_sitter_analysis else None,

        'dependency_scan': {
            'enabled': dependency_scan is not None,
            'success': dependency_scan.get('success', False) if dependency_scan else False,
            'total_dependencies': dependency_scan.get('total_dependencies', 0) if dependency_scan else 0,
            'vulnerable_dependencies': dependency_scan.get('vulnerable_dependencies', 0) if dependency_scan else 0,
            'findings': dependency_scan.get('findings', []) if dependency_scan else []
        } if dependency_scan else None,

        # Code statistics
        'code_statistics': code_index.get('statistics', {}),

        # CVE context
        'cve_context': code_index.get('cve_context', {}),

        # Recommendations
        'recommendations': tree_sitter_analysis.get('recommendations', []) if tree_sitter_analysis else [],

        # Metadata
        'analysis_metadata': {
            'tree_sitter_enabled': code_index.get('indexing_metadata', {}).get('tree_sitter_enabled', False),
            'vulnerability_scan_enabled': code_index.get('indexing_metadata', {}).get('vulnerability_scan_enabled', False),
            'patterns_checked': code_index.get('vulnerabilities', {}).get('patterns_checked', 0),
            'files_scanned': code_index.get('vulnerabilities', {}).get('files_scanned', 0)
        }
    }

    # Add success flag
    report['success'] = status != 'ERROR'

    # Add error information if present
    if status == 'ERROR':
        report['error'] = ai_analysis.get('error', 'Unknown error')

    return report


if __name__ == "__main__":
    # Example usage
    enhanced_analyze_repository_for_cve(
        job_id="test-job-id",
        repo_url="https://github.com/example/repo",
        branch="main",
        cve_id="CVE-2022-40897",
        use_tree_sitter=True,
        scan_vulnerabilities=True
    )
