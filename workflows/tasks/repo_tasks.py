"""
Repository Management Tasks

This module contains Prefect tasks for managing git repositories,
including cloning, updating, and cleaning up.
"""

import os
import shutil
import tempfile
from pathlib import Path
from prefect import task
from prefect.logging import get_run_logger
import git

@task(retries=2, retry_delay_seconds=10)
def clone_repository(repo_url: str, branch: str = "main") -> str:
    """
    Clone a GitHub repository to a temporary directory.
    
    Args:
        repo_url: URL of the repository to clone
        branch: Branch to checkout
        
    Returns:
        Path to the cloned repository
    """
    logger = get_run_logger()
    logger.info(f"Cloning repository {repo_url} (branch: {branch})")
    
    try:
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp(prefix="vuln-hunter-")
        
        # Clone the repository
        logger.info(f"Cloning to {temp_dir}...")
        repo = git.Repo.clone_from(repo_url, temp_dir, branch=branch, depth=1)
        
        logger.info(f"Successfully cloned {repo_url} to {temp_dir}")
        return temp_dir
        
    except git.exc.GitCommandError as e:
        logger.error(f"Git error: {str(e)}")
        raise RuntimeError(f"Failed to clone repository: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error cloning repository: {str(e)}")
        raise

@task
def cleanup_repository(repo_path: str):
    """
    Clean up the temporary repository directory.
    
    Args:
        repo_path: Path to the repository to clean up
    """
    logger = get_run_logger()
    
    if not repo_path or not os.path.exists(repo_path):
        logger.warning(f"Repository path {repo_path} does not exist, skipping cleanup")
        return
        
    logger.info(f"Cleaning up {repo_path}")
    
    try:
        shutil.rmtree(repo_path)
        logger.info("Cleanup complete")
    except Exception as e:
        logger.error(f"Error cleaning up repository: {str(e)}")
        # Don't raise here, cleanup failure shouldn't fail the flow
