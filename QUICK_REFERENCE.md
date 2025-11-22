# Quick Reference - Vuln-Hunter Commands

## TL;DR - Run Your Analysis NOW

```bash
cd workflows

# Your exact command - NOW ENHANCED! 🚀
uv run python run_analysis.py \
  --repo https://github.com/sureshdsk/basic-auth-django \
  --branch master \
  --cve CVE-2025-64458 \
  --detailed
```

**What's New:** Tree-sitter semantic analysis + vulnerability pre-scanning enabled by default!

## Most Common Commands

### 1. Full Analysis (Recommended)
```bash
cd workflows
uv run python run_analysis.py \
  --repo <REPO_URL> \
  --branch <BRANCH> \
  --cve <CVE_ID> \
  --detailed \
  --output report.md
```

### 2. Quick Analysis
```bash
cd workflows
uv run python run_analysis.py \
  --repo <REPO_URL> \
  --branch <BRANCH> \
  --cve <CVE_ID>
```

### 3. Save Report Only
```bash
cd workflows
uv run python run_analysis.py \
  --repo <REPO_URL> \
  --branch <BRANCH> \
  --cve <CVE_ID> \
  --output my_report.md
```

## First Time Setup (One-Time)

```bash
# 1. Install dependencies
cd workflows
uv sync

# 2. Build Tree-sitter grammars
python code_search/setup_languages.py

# 3. Set API key
export GOOGLE_API_KEY=your-key-here
```

## Command Flags Quick Reference

| Flag | What It Does | Default |
|------|-------------|---------|
| `--repo` | Repository URL | (required) |
| `--branch` | Branch name | (required) |
| `--cve` | CVE identifier | (required) |
| `--detailed` | Show full report in terminal | Off |
| `--output FILE` | Save report to file | None |
| `--no-tree-sitter` | Disable Tree-sitter (faster) | Off |
| `--no-scan` | Disable pre-scanning | Off |

## Example Use Cases

### Analyze Your Previous Repo
```bash
cd workflows
uv run python run_analysis.py \
  --repo https://github.com/sureshdsk/basic-auth-django \
  --branch master \
  --cve CVE-2025-64458 \
  --detailed
```

### Analyze Django Project
```bash
cd workflows
uv run python run_analysis.py \
  --repo https://github.com/django/django \
  --branch main \
  --cve CVE-2024-XXXX \
  --output django_analysis.md
```

### Fast Analysis (No Tree-sitter)
```bash
cd workflows
uv run python run_analysis.py \
  --repo https://github.com/user/repo \
  --branch main \
  --cve CVE-2024-XXXX \
  --no-tree-sitter \
  --no-scan
```

## What You'll See

### Enhanced Output
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

[Analysis phases...]

======================================================================
ANALYSIS RESULTS
======================================================================
Status: VULNERABLE

📊 Summary:
  Total Findings:      15
  Critical:            2
  High:                5

🔍 Analysis Sources:
  AI Agent Findings:       8
  Tree-sitter Findings:    7
  Pre-scan Findings:       5
```

## Troubleshooting

### Problem: "Tree-sitter not available"
```bash
cd workflows
python code_search/setup_languages.py
```

### Problem: "GOOGLE_API_KEY not found"
```bash
export GOOGLE_API_KEY=your-key-here
```

### Problem: "Module not found"
```bash
cd workflows
uv sync
```

## Get Help

```bash
cd workflows
uv run python run_analysis.py --help
```

## Full Documentation

- **Detailed Commands**: See [USAGE_COMMANDS.md](USAGE_COMMANDS.md)
- **Integration Guide**: See [workflows/TREE_SITTER_INTEGRATION_GUIDE.md](workflows/TREE_SITTER_INTEGRATION_GUIDE.md)
- **Full Summary**: See [INTEGRATION_SUMMARY.md](INTEGRATION_SUMMARY.md)

---

**Ready to go? Run your command now!** 🚀
