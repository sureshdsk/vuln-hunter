# Tree-sitter Code Search Module

A powerful semantic code search module built on Tree-sitter for analyzing source code and detecting vulnerabilities.

## Features

- **Multi-language Support**: Parse and search code in Python, JavaScript, TypeScript, Java, C/C++, Go, Rust, and more
- **Semantic Search**: Use Tree-sitter queries to find code patterns based on syntax tree structure
- **Vulnerability Detection**: Pre-built patterns for common security vulnerabilities (SQL injection, XSS, command injection, etc.)
- **Flexible Query Builder**: Programmatically construct Tree-sitter queries
- **Fast and Accurate**: Leverages Tree-sitter's incremental parsing for high performance

## Installation

The module requires Tree-sitter and language grammars to be installed:

```bash
# Install Tree-sitter (already in pyproject.toml)
uv add tree-sitter

# Build language grammars (see setup instructions below)
python code_search/setup_languages.py
```

## Quick Start

### 1. Basic Code Parsing

```python
from code_search import CodeParser

parser = CodeParser()

# Parse Python code
code = b"def hello(): print('Hello, World!')"
tree = parser.parse_code(code, 'python')

# Parse a file
from pathlib import Path
tree = parser.parse_file(Path('script.py'))
```

### 2. Search for Functions

```python
from code_search import CodeSearcher

searcher = CodeSearcher()

# Find all function definitions
results = searcher.find_function_definitions(Path('my_script.py'))

for result in results:
    print(f"{result.text} at line {result.line_number}")
```

### 3. Custom Tree-sitter Queries

```python
from code_search import CodeSearcher

searcher = CodeSearcher()

# Find all functions starting with 'test_'
pattern = """
(function_definition
  name: (identifier) @func_name)
(#match? @func_name "^test_")
"""

results = searcher.search_pattern(pattern, Path('test_file.py'), 'python')
```

### 4. Vulnerability Detection

```python
from code_search import CodeSearcher, VulnerabilityPatterns

searcher = CodeSearcher()

# Get all vulnerability patterns for Python
patterns = VulnerabilityPatterns.get_patterns_for_language('python')

for pattern in patterns:
    results = searcher.search_pattern(pattern.query, Path('app.py'), 'python')
    if results:
        print(f"[{pattern.severity}] {pattern.name}")
        print(f"CWE: {pattern.cwe}")
        for result in results:
            print(f"  Line {result.line_number}: {result.text}")
```

### 5. Query Builder

```python
from code_search import QueryBuilder, CodeSearcher

# Build a query to find specific function calls
query = QueryBuilder.function_calls_to('eval', 'python')

searcher = CodeSearcher()
results = searcher.search_pattern(query, Path('suspicious.py'), 'python')
```

## Module Structure

```
code_search/
├── __init__.py           # Package exports
├── parser.py             # Multi-language code parser
├── searcher.py           # Semantic code searcher
├── query_builder.py      # Query construction utilities
├── patterns.py           # Vulnerability detection patterns
├── examples.py           # Usage examples
├── README.md             # This file
└── setup_languages.py    # Language grammar setup script
```

## API Reference

### CodeParser

Main class for parsing source code with Tree-sitter.

**Methods:**
- `parse_file(file_path: Path) -> Node`: Parse a source file
- `parse_code(code: bytes, language: str) -> Node`: Parse code string
- `detect_language(file_path: Path) -> str`: Detect language from extension
- `get_node_text(node: Node, source_code: bytes) -> str`: Extract node text
- `traverse_tree(node: Node, callback: Callable)`: Traverse syntax tree

### CodeSearcher

Semantic code search using Tree-sitter queries.

**Methods:**
- `search_pattern(pattern: str, file_path: Path, language: str) -> List[SearchResult]`: Search with query
- `search_directory(pattern: str, directory: Path, ...) -> List[SearchResult]`: Search directory
- `find_function_definitions(file_path: Path) -> List[SearchResult]`: Find functions
- `find_class_definitions(file_path: Path) -> List[SearchResult]`: Find classes
- `find_imports(file_path: Path) -> List[SearchResult]`: Find imports
- `find_function_calls(file_path: Path, function_name: str) -> List[SearchResult]`: Find calls
- `custom_search(file_path: Path, node_filter: Callable) -> List[SearchResult]`: Custom filter

### VulnerabilityPatterns

Pre-built patterns for security vulnerability detection.

**Methods:**
- `get_sql_injection_patterns() -> List[VulnerabilityPattern]`
- `get_xss_patterns() -> List[VulnerabilityPattern]`
- `get_command_injection_patterns() -> List[VulnerabilityPattern]`
- `get_path_traversal_patterns() -> List[VulnerabilityPattern]`
- `get_insecure_deserialization_patterns() -> List[VulnerabilityPattern]`
- `get_hardcoded_secrets_patterns() -> List[VulnerabilityPattern]`
- `get_weak_crypto_patterns() -> List[VulnerabilityPattern]`
- `get_all_patterns() -> Dict[str, List[VulnerabilityPattern]]`
- `get_patterns_for_language(language: str) -> List[VulnerabilityPattern]`

### QueryBuilder

Utility class for building Tree-sitter queries programmatically.

**Static Methods:**
- `function_with_name(func_name: str, language: str) -> str`
- `class_with_name(class_name: str, language: str) -> str`
- `imports_from_module(module_name: str, language: str) -> str`
- `function_calls_to(func_name: str, language: str) -> str`
- `string_containing(substring: str) -> str`
- `decorators_with_name(decorator_name: str, language: str) -> str`
- `variable_assignments(var_name: str, language: str) -> str`

## Supported Languages

- Python (.py)
- JavaScript (.js, .jsx)
- TypeScript (.ts, .tsx)
- Java (.java)
- C (.c, .h)
- C++ (.cpp, .cc, .cxx, .hpp)
- Go (.go)
- Rust (.rs)
- Ruby (.rb)
- PHP (.php)
- C# (.cs)
- Swift (.swift)
- Kotlin (.kt)

## Setting Up Language Grammars

Tree-sitter requires compiled language grammars. Run the setup script:

```bash
cd workflows
python code_search/setup_languages.py
```

This will:
1. Clone Tree-sitter grammar repositories
2. Compile them into a shared library
3. Place the library in `code_search/build/languages.so`

## Tree-sitter Query Syntax

Tree-sitter queries use S-expressions to match syntax tree patterns:

```scheme
; Match function definitions
(function_definition
  name: (identifier) @function_name
  parameters: (parameters) @params)

; Match with predicates
(call_expression
  function: (identifier) @func)
(#eq? @func "dangerous_function")

; Match patterns
(string) @str
(#match? @str ".*password.*")
```

## Common Use Cases

### Find Security Issues

```python
# Find hardcoded secrets
pattern = """
(assignment
  left: (identifier) @var_name
  right: (string) @secret)
(#match? @var_name "(?i)(password|secret|api_key)")
"""
```

### Find Deprecated Functions

```python
# Find calls to deprecated functions
pattern = QueryBuilder.function_calls_to('deprecated_func', 'python')
```

### Analyze Dependencies

```python
# Find all imports
results = searcher.find_imports(Path('app.py'))
modules = [r.text for r in results]
```

### Code Metrics

```python
# Count functions and classes
functions = searcher.find_function_definitions(Path('module.py'))
classes = searcher.find_class_definitions(Path('module.py'))

print(f"Functions: {len(functions)}, Classes: {len(classes)}")
```

## Integration with Vuln-Hunter

This module is designed to integrate with the Vuln-Hunter CVE analysis workflow:

```python
from code_search import CodeSearcher, VulnerabilityPatterns
from pathlib import Path

def analyze_repository(repo_path: Path, cve_info: dict):
    searcher = CodeSearcher()

    # Get relevant patterns based on CVE type
    patterns = VulnerabilityPatterns.get_all_patterns()

    vulnerabilities = []

    # Search all Python files
    for py_file in repo_path.rglob('*.py'):
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                if pattern.language != 'python':
                    continue

                results = searcher.search_pattern(
                    pattern.query,
                    py_file,
                    'python'
                )

                for result in results:
                    vulnerabilities.append({
                        'file': str(py_file),
                        'line': result.line_number,
                        'pattern': pattern.name,
                        'severity': pattern.severity,
                        'cwe': pattern.cwe
                    })

    return vulnerabilities
```

## Examples

Run the examples script to see all features in action:

```bash
cd workflows
python -m code_search.examples
```

## Performance Tips

1. **Reuse Parser Instances**: Create one `CodeParser` and reuse it
2. **Filter by Extension**: Use `file_extensions` parameter in `search_directory()`
3. **Specific Queries**: More specific queries are faster than generic ones
4. **Incremental Parsing**: Tree-sitter supports incremental parsing for edited files

## Contributing

To add new vulnerability patterns:

1. Define the pattern in `patterns.py`
2. Include Tree-sitter query, CWE, severity
3. Test against known vulnerable code samples
4. Add to appropriate category method

## License

Part of the Vuln-Hunter project.
