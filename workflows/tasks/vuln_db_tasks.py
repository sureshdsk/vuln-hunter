"""
Vulnerability Database Tasks

This module contains Prefect tasks for interacting with vulnerability databases
like OSV.dev, NVD, etc.
"""

from prefect import task
from prefect.logging import get_run_logger
from agent.tools.cve_lookup import cve_lookup_tool

@task(retries=3, retry_delay_seconds=5)
def fetch_cve_data(cve_id: str) -> dict:
    """
    Fetch CVE information from vulnerability databases.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2022-40897")
        
    Returns:
        Dictionary containing CVE information
    """
    logger = get_run_logger()
    logger.info(f"Fetching CVE data for {cve_id}")
    
    try:
        # Use the existing tool from the agent package
        result = cve_lookup_tool(cve_id)
        
        if not result.get("success"):
            logger.warning(f"Failed to fetch CVE data: {result.get('error')}")
            # We still return the result structure even on failure, 
            # but the flow should handle the success=False flag
        else:
            logger.info(f"Successfully fetched data for {cve_id}")
            
        return result
        
    except Exception as e:
        logger.error(f"Error fetching CVE data: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "cve_id": cve_id,
            "summary": "Error fetching data"
        }
