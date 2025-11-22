"""
Code Indexer Tasks

This module contains Prefect tasks for indexing code repositories
to prepare them for analysis by the AI agent.
"""

import os
import ast
from pathlib import Path
from typing import Dict, Any, List, Optional
from prefect import task
from prefect.logging import get_run_logger

# Import Tree-sitter code search module
try:
    from code_search import CodeSearcher, VulnerabilityPatterns, CodeParser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    CodeSearcher = None
    VulnerabilityPatterns = None
    CodeParser = None

@task
def build_code_index(
    repo_path: str,
    file_pattern: str = "*.py",
    use_tree_sitter: bool = True,
    scan_vulnerabilities: bool = True,
    target_languages: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Build an enhanced code index from the repository using Tree-sitter.

    This task scans the repository for files, extracts semantic information
    using Tree-sitter, and optionally performs vulnerability pre-scanning.

    Args:
        repo_path: Path to the repository
        file_pattern: Glob pattern for files to include (default: "*.py")
        use_tree_sitter: Use Tree-sitter for enhanced analysis (default: True)
        scan_vulnerabilities: Pre-scan for vulnerabilities (default: True)
        target_languages: Languages to analyze (default: ['python'])

    Returns:
        Dictionary containing the enhanced code index with:
        - files: File-level metadata and content
        - semantic_index: Tree-sitter based semantic information
        - vulnerabilities: Pre-scanned vulnerability patterns
        - statistics: Repository statistics
    """
    logger = get_run_logger()
    logger.info(f"Building code index for {repo_path}")

    if target_languages is None:
        target_languages = ['python']

    # Check Tree-sitter availability
    if use_tree_sitter and not TREE_SITTER_AVAILABLE:
        logger.warning("Tree-sitter not available, falling back to AST-only indexing")
        use_tree_sitter = False

    # Initialize code index structure
    code_index = {
        "repo_path": repo_path,
        "files": {},
        "semantic_index": {
            "functions": [],
            "classes": [],
            "imports": [],
            "dependencies": []
        },
        "vulnerabilities": {
            "pre_scan_results": [],
            "patterns_checked": 0,
            "files_scanned": 0
        },
        "statistics": {
            "total_files": 0,
            "total_lines": 0,
            "languages": {}
        },
        "indexing_metadata": {
            "tree_sitter_enabled": use_tree_sitter,
            "vulnerability_scan_enabled": scan_vulnerabilities,
            "target_languages": target_languages
        }
    }

    try:
        # Initialize Tree-sitter searcher if available
        searcher = None
        if use_tree_sitter:
            try:
                searcher = CodeSearcher()
                logger.info("Tree-sitter code searcher initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Tree-sitter: {e}")
                use_tree_sitter = False

        # Walk through the repository
        for root, _, files in os.walk(repo_path):
            for file in files:
                # Check for Python files and dependency files
                is_python = file.endswith(".py")
                is_dependency = file in ["requirements.txt", "Pipfile", "pyproject.toml", "setup.py"]
                is_js = file.endswith((".js", ".jsx", ".ts", ".tsx"))
                is_code_file = is_python or is_js

                if not (is_code_file or is_dependency):
                    continue

                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, repo_path)

                # Skip hidden files and virtual environments
                if _should_skip_file(rel_path):
                    continue

                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    code_index["statistics"]["total_files"] += 1
                    code_index["statistics"]["total_lines"] += len(content.splitlines())

                    # Extract metadata
                    if is_python:
                        metadata = _extract_metadata_ast(content)

                        # Enhanced metadata with Tree-sitter
                        if use_tree_sitter and searcher:
                            ts_metadata = _extract_metadata_tree_sitter(
                                file_path, searcher, 'python'
                            )
                            metadata = _merge_metadata(metadata, ts_metadata)

                        # Track language stats
                        code_index["statistics"]["languages"]["python"] = \
                            code_index["statistics"]["languages"].get("python", 0) + 1

                    elif is_js:
                        if use_tree_sitter and searcher:
                            lang = 'typescript' if file.endswith(('.ts', '.tsx')) else 'javascript'
                            metadata = _extract_metadata_tree_sitter(file_path, searcher, lang)
                            code_index["statistics"]["languages"][lang] = \
                                code_index["statistics"]["languages"].get(lang, 0) + 1
                        else:
                            metadata = {"methods": [], "classes": [], "imports": []}

                    else:  # Dependency file
                        metadata = {"methods": [], "classes": [], "imports": []}

                    # Store file information
                    code_index["files"][rel_path] = {
                        "content": content,
                        "methods": metadata["methods"],
                        "classes": metadata["classes"],
                        "imports": metadata["imports"],
                        "line_count": len(content.splitlines())
                    }

                    # Update semantic index
                    for method in metadata["methods"]:
                        code_index["semantic_index"]["functions"].append({
                            "name": method,
                            "file": rel_path
                        })

                    for cls in metadata["classes"]:
                        code_index["semantic_index"]["classes"].append({
                            "name": cls,
                            "file": rel_path
                        })

                    for imp in metadata["imports"]:
                        if imp not in code_index["semantic_index"]["imports"]:
                            code_index["semantic_index"]["imports"].append(imp)

                    # Vulnerability pre-scanning
                    if scan_vulnerabilities and use_tree_sitter and is_code_file:
                        vulns = _scan_file_for_vulnerabilities(
                            file_path, searcher, rel_path
                        )
                        if vulns:
                            code_index["vulnerabilities"]["pre_scan_results"].extend(vulns)
                            code_index["vulnerabilities"]["files_scanned"] += 1

                except UnicodeDecodeError:
                    logger.warning(f"Skipping binary or non-utf8 file: {rel_path}")
                except Exception as e:
                    logger.warning(f"Error indexing file {rel_path}: {str(e)}")

        # Count patterns checked
        if scan_vulnerabilities and use_tree_sitter:
            patterns = VulnerabilityPatterns.get_all_patterns()
            code_index["vulnerabilities"]["patterns_checked"] = sum(
                len(p) for p in patterns.values()
            )

        # Log summary
        file_count = len(code_index["files"])
        vuln_count = len(code_index["vulnerabilities"]["pre_scan_results"])

        logger.info(f"Indexed {file_count} files")
        logger.info(f"Found {len(code_index['semantic_index']['functions'])} functions")
        logger.info(f"Found {len(code_index['semantic_index']['classes'])} classes")
        logger.info(f"Found {len(code_index['semantic_index']['imports'])} unique imports")

        if scan_vulnerabilities:
            logger.info(f"Pre-scan found {vuln_count} potential vulnerabilities")

        return code_index

    except Exception as e:
        logger.error(f"Error building code index: {str(e)}")
        raise

def _extract_metadata_ast(content: str) -> Dict[str, List[str]]:
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


def _extract_metadata_tree_sitter(
    file_path: str,
    searcher: 'CodeSearcher',
    language: str
) -> Dict[str, List[str]]:
    """
    Extract metadata using Tree-sitter for enhanced semantic analysis.
    """
    metadata = {
        "methods": [],
        "classes": [],
        "imports": []
    }

    try:
        file_path_obj = Path(file_path)

        # Find functions
        try:
            functions = searcher.find_function_definitions(file_path_obj)
            metadata["methods"] = [f.text.split('(')[0].strip().split()[-1] for f in functions]
        except Exception:
            pass

        # Find classes
        try:
            classes = searcher.find_class_definitions(file_path_obj)
            metadata["classes"] = [c.text.split(':')[0].strip().split()[-1] for c in classes]
        except Exception:
            pass

        # Find imports
        try:
            imports = searcher.find_imports(file_path_obj)
            for imp in imports:
                # Extract module name from import statement
                imp_text = imp.text.strip()
                if imp_text.startswith('import '):
                    modules = imp_text.replace('import ', '').split(',')
                    metadata["imports"].extend([m.strip().split()[0] for m in modules])
                elif imp_text.startswith('from '):
                    module = imp_text.split()[1]
                    metadata["imports"].append(module)
        except Exception:
            pass

    except Exception:
        # If Tree-sitter fails, return empty metadata
        pass

    return metadata


def _merge_metadata(ast_metadata: Dict, ts_metadata: Dict) -> Dict:
    """
    Merge AST and Tree-sitter metadata, preferring Tree-sitter when available.
    """
    merged = {
        "methods": [],
        "classes": [],
        "imports": []
    }

    # Use Tree-sitter results if available, otherwise fall back to AST
    for key in merged.keys():
        if ts_metadata.get(key):
            merged[key] = ts_metadata[key]
        else:
            merged[key] = ast_metadata.get(key, [])

    # Deduplicate
    for key in merged.keys():
        merged[key] = list(set(merged[key]))

    return merged


def _should_skip_file(rel_path: str) -> bool:
    """
    Check if a file should be skipped during indexing.
    """
    skip_patterns = [
        '.git', '.venv', 'venv', 'env', '__pycache__',
        'node_modules', 'dist', 'build', '.pytest_cache',
        '.mypy_cache', '.tox', 'coverage'
    ]

    # Skip hidden files
    if any(part.startswith('.') for part in rel_path.split(os.sep)):
        return True

    # Skip known directories
    for pattern in skip_patterns:
        if pattern in rel_path:
            return True

    return False


def _scan_file_for_vulnerabilities(
    file_path: str,
    searcher: 'CodeSearcher',
    rel_path: str
) -> List[Dict[str, Any]]:
    """
    Scan a file for vulnerability patterns using Tree-sitter.
    """
    vulnerabilities = []

    try:
        file_path_obj = Path(file_path)
        language = searcher.parser.detect_language(file_path_obj)

        if not language:
            return vulnerabilities

        # Get patterns for this language
        patterns = VulnerabilityPatterns.get_patterns_for_language(language)

        for pattern in patterns:
            try:
                results = searcher.search_pattern(
                    pattern.query,
                    file_path_obj,
                    language
                )

                for result in results:
                    vulnerabilities.append({
                        "file": rel_path,
                        "line": result.line_number,
                        "column": result.column,
                        "pattern_name": pattern.name,
                        "severity": pattern.severity,
                        "cwe": pattern.cwe,
                        "description": pattern.description,
                        "code_snippet": result.text[:200]  # Limit snippet size
                    })
            except Exception:
                # Pattern might not match - continue with other patterns
                continue

    except Exception:
        # If scanning fails, return empty list
        pass

    return vulnerabilities


# Legacy function name for backwards compatibility
def _extract_metadata(content: str) -> Dict[str, List[str]]:
    """Legacy function - redirects to _extract_metadata_ast."""
    return _extract_metadata_ast(content)
