"""
Code Search Tool for Google ADK Agent

This tool searches through code indexes to find vulnerable methods,
patterns, and performs basic dataflow analysis for exploitability assessment.
"""

import os
import re
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class CodeFinding(BaseModel):
    """Structured code finding model"""
    
    file_path: str = Field(description="Relative path to the file")
    line_number: int = Field(description="Line number where the finding occurs")
    method_name: str = Field(description="Method or function name")
    code_snippet: str = Field(description="Code snippet showing the finding")
    context: str = Field(description="Surrounding code context")
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence level (0.0 to 1.0)"
    )
    exploitable: Optional[bool] = Field(
        default=None,
        description="Whether this finding appears exploitable"
    )
    explanation: str = Field(
        description="Explanation of why this is flagged"
    )


def code_search_tool(
    code_index: Dict[str, Any],
    search_query: str,
    vulnerable_methods: Optional[List[str]] = None,
    file_pattern: Optional[str] = None
) -> Dict[str, Any]:
    """
    Search code for vulnerable patterns and method invocations.
    
    This tool searches through a code index (typically built from a repository)
    to find instances of vulnerable methods, patterns, or code constructs.
    It performs basic dataflow analysis to assess exploitability.
    
    Args:
        code_index: Dictionary containing code structure information
                   Expected format: {
                       "files": {
                           "path/to/file.py": {
                               "content": "file content",
                               "methods": ["method1", "method2"],
                               "imports": ["module1", "module2"]
                           }
                       },
                       "repo_path": "/path/to/repo"
                   }
        search_query: Search query or pattern to find (e.g., method name, regex pattern)
        vulnerable_methods: Optional list of known vulnerable method names to search for
        file_pattern: Optional glob pattern to filter files (e.g., "*.py")
    
    Returns:
        Dictionary containing search results:
        - findings: List of code findings with file paths and line numbers
        - total_findings: Total number of findings
        - files_searched: Number of files searched
        - success: Whether the search completed successfully
    
    Example:
        >>> code_index = {"files": {...}, "repo_path": "/repo"}
        >>> result = code_search_tool(
        ...     code_index=code_index,
        ...     search_query="unsafe_function",
        ...     vulnerable_methods=["unsafe_function", "eval"]
        ... )
        >>> print(result["total_findings"])
    """
    
    findings = []
    files_searched = 0
    
    try:
        # Validate code index structure
        if not isinstance(code_index, dict):
            return {
                "success": False,
                "error": "Invalid code_index: expected dictionary",
                "findings": [],
                "total_findings": 0,
                "files_searched": 0
            }
        
        files_data = code_index.get("files", {})
        repo_path = code_index.get("repo_path", "")
        
        if not files_data:
            return {
                "success": True,
                "error": None,
                "findings": [],
                "total_findings": 0,
                "files_searched": 0,
                "message": "No files in code index"
            }
        
        # Build search patterns
        search_patterns = []
        
        # Add search query as pattern
        if search_query:
            try:
                search_patterns.append(re.compile(search_query, re.IGNORECASE))
            except re.error:
                # If not a valid regex, treat as literal string
                search_patterns.append(re.compile(re.escape(search_query), re.IGNORECASE))
        
        # Add vulnerable methods as patterns
        if vulnerable_methods:
            for method in vulnerable_methods:
                # Match method calls: method_name( or method_name (
                pattern = rf'\b{re.escape(method)}\s*\('
                search_patterns.append(re.compile(pattern))
        
        # Search through files
        for file_path, file_info in files_data.items():
            # Apply file pattern filter if specified
            if file_pattern:
                import fnmatch
                if not fnmatch.fnmatch(file_path, file_pattern):
                    continue
            
            files_searched += 1
            content = file_info.get("content", "")
            
            if not content:
                continue
            
            lines = content.split('\n')
            
            # Search each line
            for line_num, line in enumerate(lines, start=1):
                for pattern in search_patterns:
                    matches = pattern.finditer(line)
                    
                    for match in matches:
                        # Extract method name from match
                        matched_text = match.group(0)
                        method_name = matched_text.strip().rstrip('(').strip()
                        
                        # Get context (3 lines before and after)
                        context_start = max(0, line_num - 4)
                        context_end = min(len(lines), line_num + 3)
                        context_lines = lines[context_start:context_end]
                        context = '\n'.join(
                            f"{i+context_start+1:4d}: {l}" 
                            for i, l in enumerate(context_lines)
                        )
                        
                        # Basic exploitability assessment
                        exploitable = assess_exploitability(
                            line=line,
                            method_name=method_name,
                            context_lines=context_lines,
                            file_info=file_info
                        )
                        
                        # Calculate confidence based on match type
                        confidence = calculate_confidence(
                            method_name=method_name,
                            vulnerable_methods=vulnerable_methods or [],
                            line=line,
                            file_path=file_path
                        )
                        
                        # Create finding
                        finding = CodeFinding(
                            file_path=file_path,
                            line_number=line_num,
                            method_name=method_name,
                            code_snippet=line.strip(),
                            context=context,
                            confidence=confidence,
                            exploitable=exploitable,
                            explanation=generate_explanation(
                                method_name=method_name,
                                exploitable=exploitable,
                                confidence=confidence
                            )
                        )
                        
                        findings.append(finding.model_dump())
        
        return {
            "success": True,
            "error": None,
            "findings": findings,
            "total_findings": len(findings),
            "files_searched": files_searched,
            "repo_path": repo_path
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Error during code search: {str(e)}",
            "findings": findings,  # Return any findings found before error
            "total_findings": len(findings),
            "files_searched": files_searched
        }


def assess_exploitability(
    line: str,
    method_name: str,
    context_lines: List[str],
    file_info: Dict[str, Any]
) -> bool:
    """
    Perform basic exploitability assessment.
    
    This is a simplified heuristic-based assessment. In production,
    this would use more sophisticated dataflow analysis.
    """
    
    # Check for common exploitable patterns
    exploitable_indicators = [
        'user_input', 'request.', 'input(', 'argv', 'stdin',
        'environ', 'params', 'query', 'POST', 'GET'
    ]
    
    # Check for security controls
    security_controls = [
        'sanitize', 'escape', 'validate', 'check', 'filter',
        'safe', 'secure', 'verify'
    ]
    
    # Convert context to single string
    context_text = '\n'.join(context_lines).lower()
    line_lower = line.lower()
    
    # Check for user input in context
    has_user_input = any(indicator in context_text for indicator in exploitable_indicators)
    
    # Check for security controls
    has_security_controls = any(control in context_text for control in security_controls)
    
    # Basic heuristic: exploitable if user input is present and no security controls
    if has_user_input and not has_security_controls:
        return True
    
    # Special case: certain methods are always concerning
    high_risk_methods = ['eval', 'exec', 'compile', '__import__', 'pickle.loads']
    if any(risky in method_name.lower() for risky in high_risk_methods):
        return True
    
    return False


def calculate_confidence(
    method_name: str,
    vulnerable_methods: List[str],
    line: str,
    file_path: str
) -> float:
    """
    Calculate confidence score for a finding.
    """
    
    confidence = 0.5  # Base confidence
    
    # Higher confidence if it's a known vulnerable method
    if method_name in vulnerable_methods:
        confidence += 0.3
    
    # Higher confidence for exact matches
    if any(method_name == vm for vm in vulnerable_methods):
        confidence += 0.1
    
    # Lower confidence for test files
    if 'test' in file_path.lower():
        confidence -= 0.2
    
    # Ensure confidence is in valid range
    confidence = max(0.0, min(1.0, confidence))
    
    return round(confidence, 2)


def generate_explanation(
    method_name: str,
    exploitable: Optional[bool],
    confidence: float
) -> str:
    """
    Generate explanation for the finding.
    """
    
    explanation = f"Found invocation of '{method_name}'"
    
    if exploitable:
        explanation += " which appears to be exploitable based on dataflow analysis"
    elif exploitable is False:
        explanation += " but it appears to have security controls in place"
    
    if confidence >= 0.7:
        explanation += f" (high confidence: {confidence})"
    elif confidence >= 0.4:
        explanation += f" (medium confidence: {confidence})"
    else:
        explanation += f" (low confidence: {confidence})"
    
    return explanation


# Tool metadata for Google ADK
code_search_tool.__annotations__["return"] = str
code_search_tool.__doc__ = """
Search code for vulnerable methods and patterns.

Use this tool to find instances of potentially vulnerable code in a repository.
Searches through the code index to locate method invocations, assess exploitability,
and provide detailed findings with file paths and line numbers.

Args:
    code_index: Code structure index (dictionary with files and repo_path)
    search_query: Search pattern or method name to find
    vulnerable_methods: Optional list of known vulnerable methods
    file_pattern: Optional file pattern filter (e.g., "*.py")

Returns:
    Search results with list of findings, each containing file path, line number,
    code snippet, exploitability assessment, and confidence score.
"""
