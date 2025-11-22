# Vuln-Hunter Usage Commands

Complete guide for running CVE analysis with Tree-sitter integration.

## Quick Start

### Basic Command (Your Previous Usage)

```bash
cd workflows
uv run python run_analysis.py \
  --repo https://github.com/sureshdsk/basic-auth-django \
  --branch master \
  --cve CVE-2025-64458 \
  --detailed
```

**This now uses the enhanced Tree-sitter analysis by default!**

## New Enhanced Commands

### 1. Full Enhanced Analysis (Recommended)

```bash
cd workflows
uv run python run_analysis.py \
  --repo https://github.com/sureshdsk/basic-auth-django \
  --branch master \
  --cve CVE-2025-64458 \
  --detailed \
  --output report.md
```

**Features:**
- ✅ Tree-sitter semantic analysis
- ✅ Vulnerability pre-scanning (30+ patterns)
- ✅ AI agent analysis
- ✅ Multi-language support
- ✅ Comprehensive reporting

### 2. Quick Analysis (AST Only)

```bash
cd workflows
uv run python run_analysis.py \
  --repo https://github.com/sureshdsk/basic-auth-django \
  --branch master \
  --cve CVE-2025-64458 \
  --no-tree-sitter
```

**Features:**
- AST-only analysis (faster)
- No Tree-sitter overhead
- Basic vulnerability detection

### 3. Without Pre-scanning

```bash
cd workflows
uv run python run_analysis.py \
  --repo https://github.com/sureshdsk/basic-auth-django \
  --branch master \
  --cve CVE-2025-64458 \
  --no-scan
```

**Features:**
- Tree-sitter semantic analysis
- No vulnerability pre-scanning
- AI agent analysis only

### 4. Save Report to File

```bash
cd workflows
uv run python run_analysis.py \
  --repo https://github.com/sureshdsk/basic-auth-django \
  --branch master \
  --cve CVE-2025-64458 \
  --output vulnerability_report.md
```

**Result:** Saves detailed markdown report to `vulnerability_report.md`

### 5. Analyze Different Repository

```bash
cd workflows
uv run python run_analysis.py \
  --repo https://github.com/django/django \
  --branch main \
  --cve CVE-2024-XXXX \
  --detailed
```

## Command Options

### Required Options

| Option | Description | Example |
|--------|-------------|---------|
| `--repo` | Repository URL | `--repo https://github.com/user/repo` |
| `--branch` | Branch name | `--branch main` or `--branch master` |
| `--cve` | CVE identifier | `--cve CVE-2024-1234` |

### Optional Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--detailed` | Print full report to console | Off |
| `--output FILE` | Save report to file | None |
| `--use-tree-sitter` | Enable Tree-sitter analysis | **On** |
| `--no-tree-sitter` | Disable Tree-sitter (AST only) | Off |
| `--scan-vulnerabilities` | Enable pre-scanning | **On** |
| `--no-scan` | Disable pre-scanning | Off |

## Example Use Cases

### 1. Full Analysis with Report

```bash
cd workflows
uv run python run_analysis.py \
  --repo https://github.com/sureshdsk/basic-auth-django \
  --branch master \
  --cve CVE-2025-64458 \
  --detailed \
  --output full_report.md
```

**Output:**
```
======================================================================
CVE VULNERABILITY ANALYSIS - Enhanced with Tree-sitter
======================================================================
Job ID:  abc-123-def
Repo:    https://github.com/sureshdsk/basic-auth-django
Branch:  master
CVE:     CVE-2025-64458

Enhanced Analysis Options:
  Tree-sitter:           ✓ Enabled
  Vulnerability Scan:    ✓ Enabled
======================================================================

[Analysis running...]

======================================================================
ANALYSIS RESULTS
======================================================================
Status: VULNERABLE

📊 Summary:
  Total Findings:      15
  Critical:            2
  High:                5
  Medium:              6
  Low:                 2

🔍 Analysis Sources:
  AI Agent Findings:       8
  Tree-sitter Findings:    7
  Pre-scan Findings:       5

📝 Code Statistics:
  Files Scanned:       25
  Lines of Code:       3500
  Languages: python(20), javascript(5)

Detailed report saved to: full_report.md
```

### 2. Quick Check (No Pre-scan)

```bash
cd workflows
uv run python run_analysis.py \
  --repo https://github.com/sureshdsk/basic-auth-django \
  --branch master \
  --cve CVE-2025-64458 \
  --no-scan
```

**Use When:** You want faster analysis without pre-scanning

### 3. Legacy Mode (AST Only)

```bash
cd workflows
uv run python run_analysis.py \
  --repo https://github.com/sureshdsk/basic-auth-django \
  --branch master \
  --cve CVE-2025-64458 \
  --no-tree-sitter \
  --no-scan
```

**Use When:** Tree-sitter grammars not available or debugging

### 4. Multiple Analyses

```bash
cd workflows

# Analyze multiple CVEs
uv run python run_analysis.py \
  --repo https://github.com/sureshdsk/basic-auth-django \
  --branch master \
  --cve CVE-2024-1111 \
  --output report_1111.md

uv run python run_analysis.py \
  --repo https://github.com/sureshdsk/basic-auth-django \
  --branch master \
  --cve CVE-2024-2222 \
  --output report_2222.md
```

## Setup Before First Run

### 1. Install Dependencies

```bash
cd workflows
uv sync
```

### 2. Build Tree-sitter Grammars (One-time)

```bash
cd workflows
python code_search/setup_languages.py
```

**Expected Output:**
```
Tree-sitter Language Grammar Setup
==================================================

1. Cloning language grammar repositories...
  ✓ python
  ✓ javascript
  ✓ typescript
  ...

2. Building language library...
  Building library with 12 languages...
  ✓ Library built successfully

3. Verifying installation...
  ✓ Successfully loaded Python grammar

✓ Tree-sitter setup complete and verified!
```

### 3. Set API Key (Required for AI Agent)

```bash
# Add to .env file
echo "GOOGLE_API_KEY=your-api-key-here" >> .env

# Or export in terminal
export GOOGLE_API_KEY=your-api-key-here
```

### 4. Verify Setup

```bash
cd workflows
python -m code_search.examples
```

## Troubleshooting

### "Tree-sitter not available"

```bash
# Solution: Build grammars
cd workflows
python code_search/setup_languages.py
```

### "GOOGLE_API_KEY not found"

```bash
# Solution: Set API key
export GOOGLE_API_KEY=your-key-here

# Or add to .env file
echo "GOOGLE_API_KEY=your-key" >> .env
```

### "No module named 'code_search'"

```bash
# Solution: Install dependencies
cd workflows
uv sync
```

### "Permission denied"

```bash
# Solution: Make script executable
chmod +x run_analysis.py
```

## Performance Tips

### For Large Repositories (>500 files)

```bash
# Disable pre-scan for faster analysis
uv run python run_analysis.py \
  --repo https://github.com/large/repo \
  --branch main \
  --cve CVE-2024-XXXX \
  --no-scan
```

### For Quick Checks

```bash
# Use AST-only mode
uv run python run_analysis.py \
  --repo https://github.com/user/repo \
  --branch main \
  --cve CVE-2024-XXXX \
  --no-tree-sitter
```

### For Comprehensive Analysis

```bash
# Use all features (default)
uv run python run_analysis.py \
  --repo https://github.com/user/repo \
  --branch main \
  --cve CVE-2024-XXXX \
  --detailed \
  --output full_report.md
```

## Output Examples

### Console Output (Summary)

```
======================================================================
ANALYSIS RESULTS
======================================================================
Status: VULNERABLE

📊 Summary:
  Total Findings:      15
  Critical:            2
  High:                5
  Medium:              6
  Low:                 2

🔍 Analysis Sources:
  AI Agent Findings:       8
  Tree-sitter Findings:    7
  Pre-scan Findings:       5

Findings Summary (use --detailed for full report):
- app/views.py:42 (unsafe_query)
- utils/helpers.py:128 (deserialize_data)
- api/endpoints.py:89 (execute_command)
... and 12 more.
```

### Detailed Report (--detailed flag)

Full markdown report with:
- Executive summary
- Detailed findings
- Code snippets
- Remediation recommendations
- CVE context
- Statistics

### File Output (--output flag)

Saves markdown report to specified file for:
- Documentation
- Issue tracking
- Audit trails
- Reporting

## Advanced Usage

### Batch Analysis Script

```bash
#!/bin/bash
# analyze_multiple_repos.sh

REPOS=(
  "https://github.com/user/repo1"
  "https://github.com/user/repo2"
  "https://github.com/user/repo3"
)

CVE="CVE-2024-1234"

for repo in "${REPOS[@]}"; do
  name=$(basename "$repo")
  echo "Analyzing $name..."

  cd workflows
  uv run python run_analysis.py \
    --repo "$repo" \
    --branch main \
    --cve "$CVE" \
    --output "reports/${name}_report.md"
done
```

### CI/CD Integration

```yaml
# .github/workflows/vuln-scan.yml
name: Vulnerability Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.11'

      - name: Install uv
        run: pip install uv

      - name: Run Analysis
        run: |
          cd workflows
          uv sync
          python code_search/setup_languages.py
          uv run python run_analysis.py \
            --repo ${{ github.repository }} \
            --branch ${{ github.ref_name }} \
            --cve CVE-2024-XXXX \
            --output vulnerability_report.md
        env:
          GOOGLE_API_KEY: ${{ secrets.GOOGLE_API_KEY }}

      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: vulnerability-report
          path: workflows/vulnerability_report.md
```

## Help Command

```bash
cd workflows
uv run python run_analysis.py --help
```

**Output:**
```
usage: run_analysis.py [-h] [--repo REPO] [--branch BRANCH] [--cve CVE]
                       [--detailed] [--output OUTPUT] [--use-tree-sitter]
                       [--no-tree-sitter] [--scan-vulnerabilities]
                       [--no-scan]

Run CVE analysis on a repository with Tree-sitter integration

options:
  -h, --help            show this help message and exit
  --repo REPO           Repository URL
  --branch BRANCH       Branch to analyze
  --cve CVE             CVE ID to check
  --detailed            Print detailed markdown report to console
  --output OUTPUT       Save report to file (e.g., report.md)
  --use-tree-sitter     Enable Tree-sitter semantic analysis (default: True)
  --no-tree-sitter      Disable Tree-sitter (use AST only)
  --scan-vulnerabilities
                        Enable vulnerability pre-scanning (default: True)
  --no-scan             Disable vulnerability pre-scanning
```

## Summary

**Your previous command still works, now with enhanced features:**

```bash
uv run python run_analysis.py \
  --repo https://github.com/sureshdsk/basic-auth-django \
  --branch master \
  --cve CVE-2025-64458 \
  --detailed
```

**Now includes:**
- ✅ Tree-sitter semantic analysis
- ✅ Vulnerability pre-scanning
- ✅ Multi-language support
- ✅ Enhanced reporting
- ✅ Better vulnerability detection

**All while maintaining backward compatibility!**
