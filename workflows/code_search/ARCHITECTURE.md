# Tree-sitter Code Search Architecture

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Vuln-Hunter Workflow                        │
│                    (Prefect Flow Tasks)                         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ uses
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              VulnHunterCodeAnalyzer                             │
│  • analyze_repository()                                         │
│  • analyze_for_cve()                                            │
│  • generate_report()                                            │
└────────────┬─────────────────┬──────────────────────────────────┘
             │                 │
             │                 │
    ┌────────▼───────┐   ┌────▼──────────────┐
    │ CodeSearcher   │   │ VulnerabilityPat  │
    │                │   │      terns         │
    │ • search_pat   │   │                    │
    │   tern()       │   │ • get_sql_inj...  │
    │ • find_func... │   │ • get_xss_pat...  │
    │ • find_class...│   │ • get_cmd_inj...  │
    │ • find_imports │   │ • get_all_pat...  │
    └────────┬───────┘   └────────────────────┘
             │
             │ uses
             │
    ┌────────▼───────┐   ┌──────────────────┐
    │  CodeParser    │   │  QueryBuilder    │
    │                │   │                  │
    │ • parse_file() │   │ • function_with  │
    │ • parse_code() │   │   _name()        │
    │ • traverse...  │   │ • class_with...  │
    │ • get_node...  │   │ • imports_from..│
    └────────┬───────┘   └──────────────────┘
             │
             │ uses
             │
    ┌────────▼─────────────────────────────┐
    │        Tree-sitter Library           │
    │  ┌────────────────────────────────┐  │
    │  │  Compiled Language Grammars    │  │
    │  │  • Python                      │  │
    │  │  • JavaScript/TypeScript       │  │
    │  │  • Java, C/C++, Go, Rust      │  │
    │  │  • Ruby, PHP, C#, Swift       │  │
    │  └────────────────────────────────┘  │
    └──────────────────────────────────────┘
```

## Data Flow

```
┌─────────────┐
│ Source Code │
│   Files     │
└──────┬──────┘
       │
       │ read
       ▼
┌──────────────────┐
│   CodeParser     │
│  parse_file()    │
└──────┬───────────┘
       │
       │ produces
       ▼
┌──────────────────┐
│  Syntax Tree     │
│   (AST Nodes)    │
└──────┬───────────┘
       │
       │ query with
       ▼
┌──────────────────────┐
│  Tree-sitter Query   │
│  (Pattern Matching)  │
└──────┬───────────────┘
       │
       │ returns
       ▼
┌──────────────────────┐
│   SearchResults      │
│  • file_path         │
│  • line_number       │
│  • node_type         │
│  • text              │
│  • captures          │
└──────┬───────────────┘
       │
       │ aggregate
       ▼
┌──────────────────────┐
│  Vulnerability       │
│      Report          │
└──────────────────────┘
```

## Module Interactions

### 1. Basic Code Search Flow

```python
User Code
   │
   ├─> CodeSearcher()
   │      │
   │      ├─> CodeParser()
   │      │      │
   │      │      └─> tree_sitter.Parser
   │      │
   │      └─> tree_sitter.Query
   │
   └─> SearchResult[]
```

### 2. Vulnerability Detection Flow

```python
User Code
   │
   ├─> VulnHunterCodeAnalyzer()
   │      │
   │      ├─> CodeSearcher()
   │      │      │
   │      │      └─> CodeParser()
   │      │
   │      ├─> VulnerabilityPatterns.get_all_patterns()
   │      │      │
   │      │      └─> [VulnerabilityPattern, ...]
   │      │
   │      ├─> For each pattern:
   │      │      └─> CodeSearcher.search_pattern()
   │      │
   │      └─> VulnerabilityMatch[]
   │
   └─> Report (text/JSON)
```

## Component Responsibilities

### CodeParser
**Purpose**: Low-level Tree-sitter interface
- Parse source files
- Manage language grammars
- Traverse syntax trees
- Extract node information

**Dependencies**: tree-sitter library

### CodeSearcher
**Purpose**: High-level semantic search
- Execute Tree-sitter queries
- Provide convenience methods
- Filter and aggregate results
- Handle multiple files/directories

**Dependencies**: CodeParser, tree-sitter

### VulnerabilityPatterns
**Purpose**: Security pattern library
- Define vulnerability detection patterns
- Organize by category (SQL injection, XSS, etc.)
- Map to CWE identifiers
- Support multiple languages

**Dependencies**: None (pure data)

### QueryBuilder
**Purpose**: Query construction utility
- Build queries programmatically
- Provide common query templates
- Support predicates and filters
- Reduce query syntax errors

**Dependencies**: None

### VulnHunterCodeAnalyzer
**Purpose**: High-level workflow integration
- Orchestrate repository scanning
- CVE-specific analysis
- Component usage tracking
- Report generation

**Dependencies**: CodeSearcher, VulnerabilityPatterns

## Design Patterns

### 1. Builder Pattern
**QueryBuilder** uses builder pattern for query construction:
```python
query = (QueryBuilder()
    .node('function_definition', name='(identifier) @name')
    .match_predicate('name', '^test_')
    .build())
```

### 2. Strategy Pattern
**VulnerabilityPatterns** separates pattern definitions from search logic:
```python
# Pattern (strategy)
pattern = VulnerabilityPattern(...)

# Execution
results = searcher.search_pattern(pattern.query, file, language)
```

### 3. Facade Pattern
**CodeSearcher** provides a simplified interface to Tree-sitter:
```python
# Instead of:
parser.set_language(...)
tree = parser.parse(...)
query = language.query(...)
captures = query.captures(...)

# Use:
results = searcher.find_function_definitions(file)
```

### 4. Factory Pattern
**CodeParser** creates and manages parser instances:
```python
# Lazily creates parsers for each language
parser = self.parsers.get(language)
if not parser:
    parser = self._create_parser(language)
```

## Extension Points

### 1. New Languages
Add to `CodeParser.LANGUAGE_EXTENSIONS`:
```python
LANGUAGE_EXTENSIONS = {
    '.scala': 'scala',  # New language
    # ...
}
```

### 2. New Vulnerability Patterns
Add method to `VulnerabilityPatterns`:
```python
@staticmethod
def get_my_patterns() -> List[VulnerabilityPattern]:
    return [VulnerabilityPattern(...)]
```

### 3. Custom Search Methods
Extend `CodeSearcher`:
```python
class MySearcher(CodeSearcher):
    def find_my_pattern(self, file_path: Path):
        return self.search_pattern(custom_query, file_path, ...)
```

### 4. Custom Analyzers
Extend `VulnHunterCodeAnalyzer`:
```python
class MyAnalyzer(VulnHunterCodeAnalyzer):
    def analyze_with_ai(self, repo_path: Path):
        # Custom analysis logic
        pass
```

## Performance Considerations

### Optimization Strategies

1. **Parser Reuse**: Create once, use many times
   ```python
   # Good
   searcher = CodeSearcher()  # Create once
   for file in files:
       searcher.search_pattern(...)  # Reuse

   # Bad
   for file in files:
       searcher = CodeSearcher()  # Create repeatedly
   ```

2. **File Filtering**: Skip unnecessary files early
   ```python
   if self._should_skip_file(file_path):
       continue  # Skip before parsing
   ```

3. **Specific Queries**: More specific = faster
   ```python
   # Faster
   "(function_definition name: (identifier) @name)"

   # Slower
   "(_) @anything"
   ```

4. **Incremental Parsing**: Tree-sitter supports incremental edits
   ```python
   # For future enhancement
   new_tree = parser.parse(new_code, old_tree)
   ```

### Scalability

- **Single file**: < 50ms (typical)
- **100 files**: < 5 seconds
- **1000 files**: < 1 minute
- **Memory**: ~1-5MB per file in memory

## Error Handling

### Strategy
- Fail gracefully on parsing errors
- Continue scanning remaining files
- Log errors without stopping workflow
- Return partial results

### Example
```python
try:
    results = self.search_pattern(pattern.query, file, language)
except Exception as e:
    # Log but continue
    logger.warning(f"Failed to scan {file}: {e}")
    continue
```

## Testing Strategy

### Unit Tests
- Test each component independently
- Mock Tree-sitter when needed
- Test error conditions

### Integration Tests
- Test component interactions
- Use real Tree-sitter grammars
- Test with sample code

### End-to-End Tests
- Scan real repositories
- Validate complete workflow
- Check report generation

## Security Considerations

### Code Execution
- **Safe**: Tree-sitter only parses code
- **No execution**: Code is never executed
- **Read-only**: Only reads source files

### Input Validation
- Validate file paths
- Check file sizes
- Limit recursion depth
- Skip binary files

### Output Sanitization
- Sanitize file paths in reports
- Escape special characters
- Limit output size

## Future Architecture Enhancements

1. **Caching Layer**
   ```
   CodeSearcher -> Cache -> CodeParser
   ```

2. **Parallel Processing**
   ```
   WorkQueue -> [Worker1, Worker2, ...] -> Results
   ```

3. **Plugin System**
   ```
   PluginManager -> [Plugin1, Plugin2, ...] -> CustomPatterns
   ```

4. **Database Integration**
   ```
   Results -> Database -> Historical Analysis
   ```

5. **Real-time Monitoring**
   ```
   FileWatcher -> CodeSearcher -> Alert System
   ```

## Deployment

### Installation
```bash
# 1. Install dependencies
uv add tree-sitter

# 2. Build grammars
python code_search/setup_languages.py

# 3. Verify
python -m code_search.examples
```

### Configuration
```python
# Environment variables
TREE_SITTER_LIBRARY_PATH=/path/to/languages.so

# Runtime configuration
searcher = CodeSearcher(
    parser=CodeParser(library_path=custom_path)
)
```

## Monitoring and Observability

### Metrics to Track
- Files scanned per second
- Parse errors
- Query execution time
- Memory usage
- Vulnerabilities found

### Logging
```python
import logging

logger = logging.getLogger('code_search')
logger.info(f"Scanning {file_path}")
logger.warning(f"Parse error: {error}")
logger.error(f"Fatal error: {error}")
```

## Summary

The Tree-sitter code search module provides:

- **Clean Architecture**: Separation of concerns
- **Extensible Design**: Easy to add languages/patterns
- **Performance**: Fast parsing and querying
- **Reliability**: Graceful error handling
- **Maintainability**: Well-documented and tested
- **Integration**: Ready for Vuln-Hunter workflow

This architecture supports the current needs while allowing for future enhancements and scaling.
