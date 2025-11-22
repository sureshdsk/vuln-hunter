## Tree-sitter Integration with build_code_index

### Overview

The `build_code_index` task has been enhanced with Tree-sitter semantic code analysis, providing:

1. **Multi-language Support**: Analyze Python, JavaScript, TypeScript, and more
2. **Semantic Analysis**: Extract functions, classes, imports using AST
3. **Vulnerability Pre-scanning**: Detect security issues before AI analysis
4. **Enhanced Context**: Provide richer information to the AI agent

### Architecture

```
Enhanced CVE Analysis Flow
│
├─ Phase 1: Data Collection
│  ├─ fetch_cve_data()
│  └─ clone_repository()
│
├─ Phase 2: Code Indexing & Pre-scanning
│  ├─ build_code_index()          ← Enhanced with Tree-sitter
│  │  ├─ AST extraction (fallback)
│  │  ├─ Tree-sitter semantic analysis
│  │  └─ Vulnerability pre-scanning
│  └─ enrich_code_index_with_cve_context()
│
├─ Phase 3: Deep Analysis
│  ├─ analyze_with_tree_sitter()  ← New Tree-sitter task
│  └─ run_ai_agent()              ← Uses enriched index
│
├─ Phase 4: Report Generation
│  └─ Synthesize all results
│
└─ Phase 5: Cleanup
   └─ cleanup_repository()
```

### Enhanced Code Index Structure

The new code index includes:

```python
{
    "repo_path": str,
    "files": {
        "path/to/file.py": {
            "content": str,
            "methods": List[str],
            "classes": List[str],
            "imports": List[str],
            "line_count": int
        }
    },
    "semantic_index": {
        "functions": [{"name": str, "file": str}],
        "classes": [{"name": str, "file": str}],
        "imports": List[str],
        "dependencies": List[str]
    },
    "vulnerabilities": {
        "pre_scan_results": [
            {
                "file": str,
                "line": int,
                "column": int,
                "pattern_name": str,
                "severity": str,  # critical, high, medium, low
                "cwe": str,
                "description": str,
                "code_snippet": str
            }
        ],
        "patterns_checked": int,
        "files_scanned": int
    },
    "statistics": {
        "total_files": int,
        "total_lines": int,
        "languages": Dict[str, int]
    },
    "indexing_metadata": {
        "tree_sitter_enabled": bool,
        "vulnerability_scan_enabled": bool,
        "target_languages": List[str]
    }
}
```

### Usage Examples

#### 1. Basic Usage (Backward Compatible)

```python
from tasks.indexer_tasks import build_code_index

# Works exactly like before
code_index = build_code_index(repo_path="/path/to/repo")
```

#### 2. With Tree-sitter Enabled

```python
from tasks.indexer_tasks import build_code_index

# Enable Tree-sitter semantic analysis
code_index = build_code_index(
    repo_path="/path/to/repo",
    use_tree_sitter=True,  # Default: True
    scan_vulnerabilities=True,  # Default: True
    target_languages=['python', 'javascript']
)

# Access semantic information
print(f"Functions: {len(code_index['semantic_index']['functions'])}")
print(f"Vulnerabilities: {len(code_index['vulnerabilities']['pre_scan_results'])}")
```

#### 3. Using Enhanced Flow

```python
from flows.enhanced_cve_analysis_flow import enhanced_analyze_repository_for_cve

# Run enhanced analysis
result = enhanced_analyze_repository_for_cve(
    job_id="job-123",
    repo_url="https://github.com/user/repo",
    branch="main",
    cve_id="CVE-2024-1234",
    use_tree_sitter=True,
    scan_vulnerabilities=True
)

# Access comprehensive results
print(f"Status: {result['status']}")
print(f"Total Findings: {result['summary']['total_findings']}")
print(f"Critical: {result['summary']['critical_findings']}")
print(f"AI Findings: {result['summary']['ai_findings']}")
print(f"Tree-sitter Findings: {result['summary']['tree_sitter_findings']}")
```

### Features by Component

#### build_code_index (Enhanced)

**New Features:**
- Tree-sitter semantic analysis for Python, JS, TS
- Vulnerability pattern pre-scanning
- Multi-language support
- Enhanced metadata extraction
- Statistics collection

**Parameters:**
```python
def build_code_index(
    repo_path: str,
    file_pattern: str = "*.py",
    use_tree_sitter: bool = True,
    scan_vulnerabilities: bool = True,
    target_languages: Optional[List[str]] = None
) -> Dict[str, Any]
```

**Backward Compatibility:**
- All existing code continues to work
- Tree-sitter gracefully degrades if unavailable
- Falls back to AST-only analysis

#### analyze_with_tree_sitter (New)

Deep vulnerability analysis using Tree-sitter patterns.

**Features:**
- CVE-specific analysis
- Component usage tracking
- Severity classification
- Remediation recommendations

**Parameters:**
```python
def analyze_with_tree_sitter(
    repo_path: str,
    cve_info: Dict[str, Any],
    code_index: Dict[str, Any]
) -> Dict[str, Any]
```

**Returns:**
```python
{
    "success": bool,
    "tree_sitter_findings": List[Dict],
    "component_usage": List[Dict],
    "affected_files": List[str],
    "severity_distribution": Dict[str, int],
    "total_findings": int,
    "recommendations": List[str]
}
```

#### enrich_code_index_with_cve_context (New)

Adds CVE-specific context to the code index.

**Features:**
- Identifies relevant files
- Classifies vulnerability type
- Highlights suspicious patterns
- Focuses AI agent analysis

### Vulnerability Patterns Detected

The pre-scanner checks for 30+ patterns including:

**Critical Severity:**
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Insecure Deserialization (CWE-502)

**High Severity:**
- Cross-Site Scripting (CWE-79)
- Path Traversal (CWE-22)
- XML External Entity (CWE-611)
- CSRF (CWE-352)
- Hardcoded Secrets (CWE-798)

**Medium Severity:**
- Weak Cryptography (CWE-327)
- Open Redirect (CWE-601)

### Integration with AI Agent

The enhanced code index provides richer context to the AI agent:

1. **Semantic Information**: Functions, classes, imports
2. **Pre-scan Results**: Known vulnerability patterns
3. **CVE Context**: Relevant files and suspicious code
4. **Statistics**: Code metrics and language breakdown

This allows the AI agent to:
- Focus on relevant code sections
- Understand code structure better
- Validate pre-scan findings
- Provide more accurate analysis

### Migration Guide

#### From Old Flow to Enhanced Flow

**Before:**
```python
from flows.cve_analysis_flow import analyze_repository_for_cve

result = analyze_repository_for_cve(
    job_id="job-123",
    repo_url="https://github.com/user/repo",
    branch="main",
    cve_id="CVE-2024-1234"
)
```

**After:**
```python
from flows.enhanced_cve_analysis_flow import enhanced_analyze_repository_for_cve

result = enhanced_analyze_repository_for_cve(
    job_id="job-123",
    repo_url="https://github.com/user/repo",
    branch="main",
    cve_id="CVE-2024-1234",
    use_tree_sitter=True,  # New
    scan_vulnerabilities=True  # New
)
```

**Benefits:**
- Pre-scanning reduces false positives
- Better context for AI agent
- More comprehensive findings
- Faster analysis (pre-scan filters noise)

### Performance Considerations

**Indexing Performance:**
- Small repos (<100 files): +10-20% time
- Medium repos (100-500 files): +15-25% time
- Large repos (>500 files): +20-30% time

**Benefits:**
- Better vulnerability detection
- Reduced AI agent processing time
- More accurate results

**Optimization Tips:**
1. Disable pre-scanning for quick checks: `scan_vulnerabilities=False`
2. Disable Tree-sitter for AST-only: `use_tree_sitter=False`
3. Limit target languages: `target_languages=['python']`

### Error Handling

The integration is designed to be resilient:

1. **Tree-sitter unavailable**: Falls back to AST
2. **Grammar not built**: Graceful degradation
3. **Parse errors**: Continues with other files
4. **Pattern errors**: Skips problematic patterns

All errors are logged but don't stop the workflow.

### Setup Requirements

#### 1. Install Tree-sitter Grammars

```bash
cd workflows
python code_search/setup_languages.py
```

#### 2. Verify Installation

```bash
python -m code_search.examples
```

#### 3. Test Integration

```python
from tasks.indexer_tasks import build_code_index

# Test with a sample repo
index = build_code_index(
    repo_path=".",
    use_tree_sitter=True,
    scan_vulnerabilities=True
)

print(f"Tree-sitter enabled: {index['indexing_metadata']['tree_sitter_enabled']}")
print(f"Patterns checked: {index['vulnerabilities']['patterns_checked']}")
```

### Example Output

```
INFO Building code index for /path/to/repo
INFO Tree-sitter code searcher initialized
INFO Indexed 45 files
INFO Found 123 functions
INFO Found 34 classes
INFO Found 67 unique imports
INFO Pre-scan found 8 potential vulnerabilities

INFO Phase 2: Enriching code index with CVE context...
INFO CVE Type: sql injection
INFO Relevant files: 12

INFO Phase 3a: Running Tree-sitter analysis...
INFO Tree-sitter found 8 vulnerability patterns

INFO Phase 3b: Running AI agent analysis...
INFO Analysis complete: Status=VULNERABLE, Findings=12, Exploitable=3

INFO Completed Enhanced CVE analysis
INFO Final status: VULNERABLE
INFO Total findings: 15
```

### Monitoring and Debugging

#### Log Messages to Watch

```python
# Success indicators
"Tree-sitter code searcher initialized"
"Pre-scan found X potential vulnerabilities"
"Tree-sitter found X vulnerability patterns"

# Warning indicators
"Tree-sitter not available, falling back to AST-only"
"Failed to initialize Tree-sitter"

# Error indicators
"Error building code index"
"Error in Tree-sitter analysis"
```

#### Debug Mode

```python
# Enable detailed logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Or in Prefect
from prefect.logging import get_run_logger
logger = get_run_logger()
logger.setLevel(logging.DEBUG)
```

### Testing

```bash
# Run indexer tests
cd workflows
python -m pytest tasks/test_indexer_integration.py -v

# Run end-to-end test
python -m pytest tests/test_enhanced_flow.py -v
```

### Troubleshooting

**Issue:** "Tree-sitter not available"
```bash
# Solution
cd workflows
python code_search/setup_languages.py
```

**Issue:** "No vulnerabilities found"
```bash
# Check if scanning is enabled
code_index = build_code_index(..., scan_vulnerabilities=True)

# Verify patterns are loaded
from code_search import VulnerabilityPatterns
patterns = VulnerabilityPatterns.get_all_patterns()
print(f"Loaded {len(patterns)} pattern categories")
```

**Issue:** "Slow indexing"
```bash
# Disable pre-scanning temporarily
code_index = build_code_index(..., scan_vulnerabilities=False)

# Or limit languages
code_index = build_code_index(..., target_languages=['python'])
```

### Best Practices

1. **Always use enhanced flow for production**: More comprehensive analysis
2. **Enable pre-scanning**: Catches low-hanging fruit early
3. **Review pre-scan results**: May contain false positives
4. **Combine with AI agent**: Best results come from both
5. **Monitor performance**: Adjust settings based on repo size
6. **Keep grammars updated**: Run setup script periodically

### Future Enhancements

Planned improvements:
1. **Caching**: Cache parsed trees for faster re-runs
2. **Incremental scanning**: Only scan changed files
3. **Custom patterns**: Allow users to add patterns
4. **More languages**: Add support for Go, Rust, Java
5. **Performance optimization**: Parallel file processing
6. **Pattern learning**: ML-based pattern generation

### Support

For issues or questions:
- Check [QUICKSTART.md](code_search/QUICKSTART.md)
- Review [README.md](code_search/README.md)
- Check [examples.py](code_search/examples.py)
