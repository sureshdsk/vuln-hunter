"""
AI Agent Tasks

This module contains Prefect tasks for running the Google ADK agent
to analyze vulnerabilities.
"""

from prefect import task
from prefect.logging import get_run_logger
from agent.vulnerability_agent import analyze_cve_vulnerability

@task
def run_ai_agent(
    cve_info: dict, 
    code_index: dict, 
    job_id: str, 
    repo_url: str, 
    branch: str
) -> dict:
    """
    Run AI agent analysis using Google ADK.
    
    Args:
        cve_info: CVE information dictionary
        code_index: Code index dictionary
        job_id: Job identifier
        repo_url: Repository URL
        branch: Branch name
        
    Returns:
        Analysis results dictionary
    """
    logger = get_run_logger()
    logger.info(f"Running ADK agent analysis for job {job_id}")
    
    try:
        # Extract CVE ID from cve_info
        cve_id = cve_info.get("cve_id")
        
        if not cve_id:
            logger.error("No CVE ID provided in cve_info")
            return {
                "success": False,
                "error": "No CVE ID provided",
                "findings": [],
                "status": "ERROR"
            }
        
        # Run the vulnerability analysis
        logger.info(f"Analyzing {cve_id} using ADK agent...")
        
        analysis = analyze_cve_vulnerability(
            cve_id=cve_id,
            code_index=code_index,
            job_id=job_id,
            repository_url=repo_url,
            branch=branch
        )
        
        # Log results
        if analysis.get("success"):
            status = analysis.get("status", "UNKNOWN")
            total_findings = analysis.get("total_findings", 0)
            exploitable = analysis.get("exploitable_findings", 0)
            
            logger.info(f"Analysis complete: Status={status}, Findings={total_findings}, Exploitable={exploitable}")
        else:
            logger.error(f"Analysis failed: {analysis.get('error')}")
        
        return analysis
        
    except ImportError as e:
        logger.error(f"Failed to import vulnerability agent: {str(e)}")
        logger.warning("Make sure GOOGLE_API_KEY environment variable is set")
        return {
            "success": False,
            "error": f"Agent import failed: {str(e)}",
            "findings": [],
            "status": "ERROR"
        }
    except Exception as e:
        logger.error(f"Unexpected error in AI agent analysis: {str(e)}")
        return {
            "success": False,
            "error": f"Analysis error: {str(e)}",
            "findings": [],
            "status": "ERROR"
        }
