# Tree-sitter Integration Visual Diagram

## Complete System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Vuln-Hunter System                           │
│                   Enhanced CVE Analysis Workflow                    │
└─────────────────────────────────────────────────────────────────────┘

                    ┌──────────────────┐
                    │   User Request   │
                    │  job_id, repo,   │
                    │  branch, cve_id  │
                    └────────┬─────────┘
                             │
                             ↓
┌────────────────────────────────────────────────────────────────────┐
│ PHASE 1: Data Collection                                          │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────────┐        ┌─────────────────────┐             │
│  │ fetch_cve_data() │        │ clone_repository()  │             │
│  │                  │        │                     │             │
│  │ • Fetch from NVD │        │ • Clone from GitHub │             │
│  │ • Fetch from OSV │        │ • Checkout branch   │             │
│  │ • Parse CVE data │        │ • Validate repo     │             │
│  └────────┬─────────┘        └──────────┬──────────┘             │
│           │                             │                         │
│           │ cve_info                    │ repo_path               │
│           └──────────────┬──────────────┘                         │
│                          ↓                                         │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│ PHASE 2: Code Indexing & Pre-scanning                             │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ build_code_index() - ENHANCED                            │    │
│  │                                                          │    │
│  │  ┌────────────────┐     ┌──────────────────────────┐    │    │
│  │  │ AST Analysis   │     │ Tree-sitter Analysis     │    │    │
│  │  │                │     │                          │    │    │
│  │  │ • Parse Python │     │ • Multi-language parsing │    │    │
│  │  │ • Extract:     │     │ • Semantic extraction    │    │    │
│  │  │   - Functions  │ +   │ • Enhanced metadata      │    │    │
│  │  │   - Classes    │     │ • Cross-references       │    │    │
│  │  │   - Imports    │     │                          │    │    │
│  │  └────────────────┘     └──────────────────────────┘    │    │
│  │                                                          │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │ Vulnerability Pre-scanning                      │    │    │
│  │  │                                                 │    │    │
│  │  │ • 30+ security patterns                        │    │    │
│  │  │ • SQL Injection (CWE-89)                       │    │    │
│  │  │ • XSS (CWE-79)                                │    │    │
│  │  │ • Command Injection (CWE-78)                  │    │    │
│  │  │ • Path Traversal (CWE-22)                     │    │    │
│  │  │ • And more...                                 │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  │                                                          │    │
│  │  Output:                                                │    │
│  │  {                                                      │    │
│  │    files: {...},                                        │    │
│  │    semantic_index: {...},                              │    │
│  │    vulnerabilities: {pre_scan_results: [...]},         │    │
│  │    statistics: {...}                                    │    │
│  │  }                                                      │    │
│  └──────────────────────────┬───────────────────────────────┘    │
│                             │ code_index                         │
│                             ↓                                     │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ enrich_code_index_with_cve_context()                     │    │
│  │                                                          │    │
│  │ • Classify vulnerability type                           │    │
│  │ • Find relevant files                                   │    │
│  │ • Identify suspicious patterns                          │    │
│  │ • Extract affected components                           │    │
│  │                                                          │    │
│  │ Output: enriched_index                                  │    │
│  └──────────────────────────┬───────────────────────────────┘    │
│                             │                                     │
└─────────────────────────────┼─────────────────────────────────────┘
                              │
                              ↓
┌────────────────────────────────────────────────────────────────────┐
│ PHASE 3: Deep Analysis (Parallel Execution)                       │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌───────────────────────────────┐  ┌──────────────────────────┐  │
│  │ analyze_with_tree_sitter()    │  │ run_ai_agent()           │  │
│  │                               │  │                          │  │
│  │ • CVE-specific patterns       │  │ • Google ADK agent       │  │
│  │ • Component usage tracking    │  │ • Enriched context       │  │
│  │ • Severity classification     │  │ • Deep analysis          │  │
│  │ • File-level findings         │  │ • Exploit validation     │  │
│  │                               │  │                          │  │
│  │ Uses:                         │  │ Uses:                    │  │
│  │ • VulnHunterCodeAnalyzer      │  │ • vulnerability_agent    │  │
│  │ • VulnerabilityPatterns       │  │ • enriched_index         │  │
│  │ • CodeSearcher                │  │                          │  │
│  │                               │  │                          │  │
│  │ Output: tree_sitter_analysis  │  │ Output: ai_analysis      │  │
│  └───────────────┬───────────────┘  └──────────┬───────────────┘  │
│                  │                              │                  │
│                  └──────────────┬───────────────┘                  │
│                                 ↓                                  │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│ PHASE 4: Report Generation & Synthesis                            │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ _synthesize_results()                                    │    │
│  │                                                          │    │
│  │ Combine findings from:                                   │    │
│  │ • AST analysis                                          │    │
│  │ • Tree-sitter semantic analysis                         │    │
│  │ • Vulnerability pre-scan                                │    │
│  │ • Tree-sitter deep analysis                             │    │
│  │ • AI agent analysis                                     │    │
│  │                                                          │    │
│  │ Generate:                                               │    │
│  │ • Unified findings list                                 │    │
│  │ • Severity distribution                                 │    │
│  │ • Affected files                                        │    │
│  │ • Recommendations                                       │    │
│  │ • Statistics                                            │    │
│  │                                                          │    │
│  └──────────────────────────┬───────────────────────────────┘    │
│                             ↓                                     │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ Comprehensive Report                                     │    │
│  │                                                          │    │
│  │ {                                                        │    │
│  │   job_id: "...",                                        │    │
│  │   status: "VULNERABLE",                                 │    │
│  │   findings: [                                           │    │
│  │     {source: "tree-sitter", ...},                      │    │
│  │     {source: "ai-agent", ...},                         │    │
│  │   ],                                                    │    │
│  │   summary: {                                            │    │
│  │     total_findings: 15,                                 │    │
│  │     critical_findings: 2,                               │    │
│  │     ai_findings: 8,                                     │    │
│  │     tree_sitter_findings: 7                             │    │
│  │   },                                                    │    │
│  │   recommendations: [...]                                │    │
│  │ }                                                        │    │
│  └──────────────────────────┬───────────────────────────────┘    │
│                             ↓                                     │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│ PHASE 5: Cleanup                                                  │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ cleanup_repository()                                     │    │
│  │                                                          │    │
│  │ • Remove cloned repository                              │    │
│  │ • Clean up temp files                                   │    │
│  │ • Free resources                                        │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘

                             ↓
                    ┌──────────────────┐
                    │  Final Report    │
                    │  to User/System  │
                    └──────────────────┘
```

## Data Flow Details

### Enhanced Code Index Structure

```
code_index = {
    repo_path: str,

    files: {
        "app.py": {
            content: str,         # Full file content
            methods: [str],       # Function names
            classes: [str],       # Class names
            imports: [str],       # Import statements
            line_count: int       # Number of lines
        }
    },

    semantic_index: {
        functions: [
            {name: "function_name", file: "app.py"}
        ],
        classes: [
            {name: "ClassName", file: "app.py"}
        ],
        imports: ["os", "subprocess", ...],
        dependencies: [...]
    },

    vulnerabilities: {
        pre_scan_results: [
            {
                file: "app.py",
                line: 42,
                column: 8,
                pattern_name: "SQL Injection - String Concatenation",
                severity: "critical",
                cwe: "CWE-89",
                description: "...",
                code_snippet: "..."
            }
        ],
        patterns_checked: 30,
        files_scanned: 15
    },

    statistics: {
        total_files: 25,
        total_lines: 3500,
        languages: {
            python: 20,
            javascript: 5
        }
    },

    indexing_metadata: {
        tree_sitter_enabled: true,
        vulnerability_scan_enabled: true,
        target_languages: ["python", "javascript"]
    }
}
```

### Analysis Results Flow

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│ Pre-scan    │    │ Tree-sitter  │    │ AI Agent    │
│ Results     │───▶│ Deep         │───▶│ Analysis    │
│             │    │ Analysis     │    │             │
│ 8 findings  │    │ 7 findings   │    │ 8 findings  │
└─────────────┘    └──────────────┘    └─────────────┘
                                              │
                                              ↓
                                    ┌──────────────────┐
                                    │ Synthesis        │
                                    │                  │
                                    │ Deduplicates     │
                                    │ Enriches context │
                                    │ Ranks findings   │
                                    └────────┬─────────┘
                                             │
                                             ↓
                                    ┌──────────────────┐
                                    │ Final Report     │
                                    │                  │
                                    │ 15 unique        │
                                    │ findings         │
                                    │                  │
                                    │ With context,    │
                                    │ recommendations, │
                                    │ and priorities   │
                                    └──────────────────┘
```

## Module Interactions

```
┌──────────────────────────────────────────────────────────────┐
│ Enhanced CVE Analysis Flow                                  │
│ (flows/enhanced_cve_analysis_flow.py)                       │
└────────┬─────────────────────────────────────────────┬───────┘
         │                                             │
         │ imports                                     │ imports
         ↓                                             ↓
┌────────────────────┐                    ┌────────────────────┐
│ Indexer Tasks      │                    │ Enhanced Indexer   │
│ (indexer_tasks.py) │                    │ Tasks              │
│                    │                    │ (enhanced_indexer_ │
│ • build_code_index │                    │  tasks.py)         │
│                    │                    │                    │
│                    │                    │ • analyze_with_    │
│                    │                    │   tree_sitter      │
│                    │                    │ • enrich_code_     │
│                    │                    │   index_with_cve_  │
│                    │                    │   context          │
└────────┬───────────┘                    └────────┬───────────┘
         │                                         │
         │ imports                                 │ imports
         ↓                                         ↓
┌──────────────────────────────────────────────────────────────┐
│ Code Search Module                                           │
│ (code_search/)                                               │
│                                                              │
│ ┌──────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│ │ Parser   │  │ Searcher     │  │ Vulnerability         │  │
│ │          │  │              │  │ Patterns              │  │
│ │          │  │              │  │                       │  │
│ │ • parse  │  │ • search     │  │ • 30+ patterns        │  │
│ │ • detect │  │ • find_funcs │  │ • get_patterns_for_   │  │
│ │   lang   │  │ • find_class │  │   language            │  │
│ └──────────┘  └──────────────┘  └───────────────────────┘  │
│                                                              │
│ ┌──────────────────┐  ┌──────────────────────────────────┐  │
│ │ QueryBuilder     │  │ VulnHunterCodeAnalyzer          │  │
│ │                  │  │                                  │  │
│ │ • build queries  │  │ • analyze_repository             │  │
│ │ • predicates     │  │ • analyze_for_cve               │  │
│ └──────────────────┘  └──────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Backward Compatibility

```
┌─────────────────────────────────────────────────────────────┐
│ Original Flow                                               │
│ (cve_analysis_flow.py)                                      │
│                                                             │
│ ┌─────────────────┐                                         │
│ │ build_code_index│  ─────▶  Still works!                  │
│ │ (repo_path)     │          Uses AST only                 │
│ └─────────────────┘          Default behavior unchanged     │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Enhanced Flow                                               │
│ (enhanced_cve_analysis_flow.py)                             │
│                                                             │
│ ┌─────────────────┐                                         │
│ │ build_code_index│  ─────▶  Enhanced!                     │
│ │ (repo_path,     │          AST + Tree-sitter             │
│ │  use_ts=True,   │          + Vulnerability scanning      │
│ │  scan_v=True)   │          + Statistics                  │
│ └─────────────────┘                                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

