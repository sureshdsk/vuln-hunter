# Quick Start Guide - Tree-sitter Code Search

This guide will help you get started with the Tree-sitter code search module in under 5 minutes.

## Step 1: Setup Tree-sitter Grammars (One-time)

Before using the module, you need to build the Tree-sitter language grammars:

```bash
cd workflows
python code_search/setup_languages.py
```

This will:
- Clone Tree-sitter grammar repositories for popular languages
- Compile them into a shared library
- Place the library at `code_search/build/languages.so`

**Note:** This requires `git` and a C compiler (`gcc` or `clang`).

## Step 2: Run Examples

Try the examples to see the module in action:

```bash
cd workflows
python -m code_search.examples
```

This will demonstrate:
- Basic code parsing
- Finding functions and classes
- Custom queries
- Vulnerability detection
- Directory-wide searches

## Step 3: Basic Usage

### Parse and Search Code

```python
from code_search import CodeParser, CodeSearcher
from pathlib import Path

# Initialize searcher
searcher = CodeSearcher()

# Find all functions in a file
results = searcher.find_function_definitions(Path('my_script.py'))

for result in results:
    print(f"Function '{result.text}' at line {result.line_number}")
```

### Detect Vulnerabilities

```python
from code_search import CodeSearcher, VulnerabilityPatterns

searcher = CodeSearcher()

# Get vulnerability patterns for Python
patterns = VulnerabilityPatterns.get_patterns_for_language('python')

# Scan a file
for pattern in patterns:
    results = searcher.search_pattern(pattern.query, Path('app.py'), 'python')

    if results:
        print(f"\n[{pattern.severity}] {pattern.name}")
        print(f"CWE: {pattern.cwe}")

        for result in results:
            print(f"  Line {result.line_number}: {result.text[:60]}")
```

### Custom Tree-sitter Queries

```python
from code_search import CodeSearcher

searcher = CodeSearcher()

# Find all test functions (functions starting with 'test_')
pattern = """
(function_definition
  name: (identifier) @func_name)
(#match? @func_name "^test_")
"""

results = searcher.search_pattern(pattern, Path('test_file.py'), 'python')
```

## Step 4: Integration with Vuln-Hunter

Use the analyzer for complete vulnerability scanning:

```python
from code_search.integration_example import VulnHunterCodeAnalyzer
from pathlib import Path

analyzer = VulnHunterCodeAnalyzer()

# Analyze a repository
results = analyzer.analyze_repository(
    repo_path=Path('/path/to/repo'),
    target_languages=['python', 'javascript'],
    severity_filter=['critical', 'high']
)

# Generate report
report = analyzer.generate_report(results)
print(report)

# Save JSON report
analyzer.generate_report(results, Path('report.json'))
```

## Common Use Cases

### 1. Find All Imports

```python
searcher = CodeSearcher()
imports = searcher.find_imports(Path('module.py'))

for imp in imports:
    print(imp.text)
```

### 2. Find Function Calls

```python
# Find all calls to a specific function
results = searcher.find_function_calls(
    Path('app.py'),
    function_name='dangerous_function'
)
```

### 3. Search for Hardcoded Secrets

```python
patterns = VulnerabilityPatterns.get_hardcoded_secrets_patterns()

for pattern in patterns:
    results = searcher.search_pattern(pattern.query, Path('config.py'), 'python')

    for result in results:
        print(f"Potential secret at line {result.line_number}")
```

### 4. Scan Entire Directory

```python
pattern = "(function_definition name: (identifier) @func)"

results = searcher.search_directory(
    pattern=pattern,
    directory=Path('src'),
    file_extensions=['.py'],
    exclude_patterns=['**/test_*', '**/__pycache__/*']
)

print(f"Found {len(results)} functions across all files")
```

## Supported Languages

The module supports:
- Python (`.py`)
- JavaScript (`.js`, `.jsx`)
- TypeScript (`.ts`, `.tsx`)
- Java (`.java`)
- C (`.c`, `.h`)
- C++ (`.cpp`, `.hpp`)
- Go (`.go`)
- Rust (`.rs`)

## Troubleshooting

### Tree-sitter grammars not found

If you get an error about missing grammars:

```bash
# Run the setup script
python code_search/setup_languages.py
```

### Compilation errors

Make sure you have a C compiler installed:
- **macOS**: Install Xcode Command Line Tools (`xcode-select --install`)
- **Linux**: Install GCC (`sudo apt-get install gcc` or `sudo yum install gcc`)

### No results found

Check that:
1. The file path is correct
2. The language is supported
3. The query pattern matches the language's syntax tree structure

## Next Steps

- Read the full [README.md](README.md) for detailed API documentation
- Check out [examples.py](examples.py) for more code samples
- Review [patterns.py](patterns.py) to see available vulnerability patterns
- Explore [integration_example.py](integration_example.py) for workflow integration

## Getting Help

- Check the [Tree-sitter documentation](https://tree-sitter.github.io/tree-sitter/)
- Review [Tree-sitter query syntax](https://tree-sitter.github.io/tree-sitter/using-parsers#pattern-matching-with-queries)
- Look at language-specific grammar repositories for node types

## Performance Tips

1. **Reuse parser instances** - Create once, use many times
2. **Filter file extensions** - Only scan relevant files
3. **Use specific queries** - More specific patterns are faster
4. **Exclude test/vendor directories** - Skip unnecessary files

Happy code hunting! 🔍
