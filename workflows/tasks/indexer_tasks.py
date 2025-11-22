"""
Code Indexer Tasks

This module contains Prefect tasks for indexing code repositories
to prepare them for analysis by the AI agent.
"""

import os
import ast
from typing import Dict, Any, List
from prefect import task
from prefect.logging import get_run_logger

@task
def build_code_index(repo_path: str, file_pattern: str = "*.py") -> Dict[str, Any]:
    """
    Build a code index from the repository.
    
    This task scans the repository for files matching the pattern,
    reads their content, and extracts basic metadata (methods, imports).
    
    Args:
        repo_path: Path to the repository
        file_pattern: Glob pattern for files to include (default: "*.py")
        
    Returns:
        Dictionary containing the code index
    """
    logger = get_run_logger()
    logger.info(f"Building code index for {repo_path}")
    
    code_index = {
        "repo_path": repo_path,
        "files": {}
    }
    
    try:
        # Walk through the repository
        for root, _, files in os.walk(repo_path):
            for file in files:
                # Check for Python files and dependency files
                is_python = file.endswith(".py")
                is_dependency = file in ["requirements.txt", "Pipfile", "pyproject.toml", "setup.py"]
                
                if not (is_python or is_dependency):
                    continue
                    
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, repo_path)
                
                # Skip hidden files and virtual environments
                if any(part.startswith('.') for part in rel_path.split(os.sep)):
                    continue
                if "venv" in rel_path or "env" in rel_path:
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    # Extract metadata using AST
                    metadata = _extract_metadata(content)
                    
                    code_index["files"][rel_path] = {
                        "content": content,
                        "methods": metadata["methods"],
                        "classes": metadata["classes"],
                        "imports": metadata["imports"]
                    }
                    
                except UnicodeDecodeError:
                    logger.warning(f"Skipping binary or non-utf8 file: {rel_path}")
                except Exception as e:
                    logger.warning(f"Error indexing file {rel_path}: {str(e)}")
        
        file_count = len(code_index["files"])
        logger.info(f"Indexed {file_count} files")
        
        return code_index
        
    except Exception as e:
        logger.error(f"Error building code index: {str(e)}")
        raise

def _extract_metadata(content: str) -> Dict[str, List[str]]:
    """
    Extract metadata (methods, classes, imports) from Python code using AST.
    """
    metadata = {
        "methods": [],
        "classes": [],
        "imports": []
    }
    
    try:
        tree = ast.parse(content)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                metadata["methods"].append(node.name)
            elif isinstance(node, ast.ClassDef):
                metadata["classes"].append(node.name)
            elif isinstance(node, ast.Import):
                for name in node.names:
                    metadata["imports"].append(name.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    metadata["imports"].append(node.module)
                    
    except SyntaxError:
        # If code has syntax errors, we just skip metadata extraction
        pass
        
    return metadata
