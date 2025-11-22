"""
Prefect workflow for CVE analysis
"""

from prefect import flow
from prefect.logging import get_run_logger

# Import tasks
from tasks.vuln_db_tasks import fetch_cve_data
from tasks.repo_tasks import clone_repository, cleanup_repository
from tasks.indexer_tasks import build_code_index
from tasks.agent_tasks import run_ai_agent


@flow(name="CVE Analysis Flow")
def analyze_repository_for_cve(
    job_id: str,
    repo_url: str,
    branch: str,
    cve_id: str
):
    """
    Main CVE analysis workflow
    
    Args:
        job_id: UUID of the analysis job
        repo_url: GitHub repository URL
        branch: Branch to analyze
        cve_id: CVE identifier
    """
    logger = get_run_logger()
    logger.info(f"Starting CVE analysis for job {job_id}")
    logger.info(f"Repository: {repo_url}, Branch: {branch}, CVE: {cve_id}")
    
    repo_path = None
    
    try:
        # 1. Fetch CVE data
        cve_info = fetch_cve_data(cve_id)
        
        if not cve_info.get("success"):
            logger.error(f"Aborting analysis: {cve_info.get('error')}")
            return {
                "job_id": job_id,
                "status": "ERROR",
                "error": cve_info.get("error")
            }
        
        # 2. Clone repository
        repo_path = clone_repository(repo_url, branch)
        
        # 3. Build code index
        code_index = build_code_index(repo_path)
        
        # 4. Run AI agent analysis with ADK
        analysis = run_ai_agent(
            cve_info=cve_info,
            code_index=code_index,
            job_id=job_id,
            repo_url=repo_url,
            branch=branch
        )
        
        # 5. Generate report (report is already included in analysis from agent)
        # The ADK agent returns a complete report, so we can use it directly
        report = analysis
        
        logger.info(f"Completed CVE analysis for job {job_id}")
        logger.info(f"Final status: {report.get('status', 'UNKNOWN')}")
        
        return report
        
    except Exception as e:
        logger.error(f"Error in CVE analysis workflow: {str(e)}")
        # Return error report structure
        return {
            "job_id": job_id,
            "status": "ERROR",
            "error": str(e)
        }
    finally:
        # 6. Cleanup (always run)
        if repo_path:
            cleanup_repository(repo_path)


if __name__ == "__main__":
    # Example usage
    analyze_repository_for_cve(
        job_id="test-job-id",
        repo_url="https://github.com/example/repo",
        branch="main",
        cve_id="CVE-2022-40897"
    )
