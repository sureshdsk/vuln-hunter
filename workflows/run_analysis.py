"""
Script to run the CVE analysis flow manually.
"""

import os
import sys
import uuid
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# Add the workflows directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flows.enhanced_cve_analysis_flow import enhanced_analyze_repository_for_cve

import argparse

def main():
    parser = argparse.ArgumentParser(description="Run CVE analysis on a repository with Tree-sitter integration")
    parser.add_argument("--repo", default="https://github.com/sureshdsk/basic-auth-django", help="Repository URL")
    parser.add_argument("--branch", default="master", help="Branch to analyze")
    parser.add_argument("--cve", default="CVE-2025-64458", help="CVE ID to check")
    parser.add_argument("--detailed", action="store_true", help="Print detailed markdown report to console")
    parser.add_argument("--output", help="Save report to file (e.g., report.md)")

    # Tree-sitter options
    parser.add_argument("--use-tree-sitter", action="store_true", default=True,
                        help="Enable Tree-sitter semantic analysis (default: True)")
    parser.add_argument("--no-tree-sitter", action="store_true",
                        help="Disable Tree-sitter (use AST only)")
    parser.add_argument("--scan-vulnerabilities", action="store_true", default=True,
                        help="Enable vulnerability pre-scanning (default: True)")
    parser.add_argument("--no-scan", action="store_true",
                        help="Disable vulnerability pre-scanning")

    args = parser.parse_args()

    # Handle Tree-sitter flags
    use_tree_sitter = args.use_tree_sitter and not args.no_tree_sitter
    scan_vulnerabilities = args.scan_vulnerabilities and not args.no_scan

    # Configuration
    repo_url = args.repo
    branch = args.branch
    cve_id = args.cve
    job_id = str(uuid.uuid4())

    print("="*70)
    print("CVE VULNERABILITY ANALYSIS - Enhanced with Tree-sitter")
    print("="*70)
    print(f"Job ID:  {job_id}")
    print(f"Repo:    {repo_url}")
    print(f"Branch:  {branch}")
    print(f"CVE:     {cve_id}")
    print(f"\nEnhanced Analysis Options:")
    print(f"  Tree-sitter:           {'✓ Enabled' if use_tree_sitter else '✗ Disabled'}")
    print(f"  Vulnerability Scan:    {'✓ Enabled' if scan_vulnerabilities else '✗ Disabled'}")
    print("="*70)
    
    # Check for API Key
    if not os.getenv("GOOGLE_API_KEY"):
        print("WARNING: GOOGLE_API_KEY not found in environment.")
        print("The AI agent analysis might fail or return limited results.")
        # You might want to uncomment this to enforce the key
        # sys.exit(1)

    try:
        result = enhanced_analyze_repository_for_cve(
            job_id=job_id,
            repo_url=repo_url,
            branch=branch,
            cve_id=cve_id,
            use_tree_sitter=use_tree_sitter,
            scan_vulnerabilities=scan_vulnerabilities
        )
        
        print("\n" + "="*70)
        print("ANALYSIS RESULTS")
        print("="*70)
        print(f"Status: {result.get('status')}")

        if result.get('status') == 'ERROR':
            print(f"Error: {result.get('error')}")
        else:
            # Display summary
            summary = result.get('summary', {})
            print(f"\n📊 Summary:")
            print(f"  Total Findings:      {summary.get('total_findings', 0)}")
            print(f"  Critical:            {summary.get('critical_findings', 0)}")
            print(f"  High:                {summary.get('high_findings', 0)}")
            print(f"  Medium:              {summary.get('medium_findings', 0)}")
            print(f"  Low:                 {summary.get('low_findings', 0)}")

            # Enhanced analysis breakdown
            if use_tree_sitter:
                print(f"\n🔍 Analysis Sources:")
                print(f"  AI Agent Findings:       {summary.get('ai_findings', 0)}")
                print(f"  Tree-sitter Findings:    {summary.get('tree_sitter_findings', 0)}")
                print(f"  Pre-scan Findings:       {summary.get('pre_scan_findings', 0)}")
                print(f"  Dependency Findings:     {summary.get('dependency_findings', 0)}")

            # Dependency scan results
            if 'dependency_scan' in result and result['dependency_scan']:
                dep_scan = result['dependency_scan']
                print(f"\n📦 Dependency Analysis:")
                print(f"  Total Dependencies:      {dep_scan.get('total_dependencies', 0)}")
                print(f"  Vulnerable Dependencies: {dep_scan.get('vulnerable_dependencies', 0)}")

                if dep_scan.get('vulnerable_dependencies', 0) > 0:
                    print(f"\n  ⚠️  Vulnerable Packages Found:")
                    for finding in dep_scan.get('findings', []):
                        print(f"    - {finding.get('package')} {finding.get('installed_version')}")
                        print(f"      CVE: {finding.get('cve_id')}")
                        print(f"      Reason: {finding.get('reason')}")

            # Code statistics
            if 'code_statistics' in result:
                stats = result['code_statistics']
                print(f"\n📝 Code Statistics:")
                print(f"  Files Scanned:       {stats.get('total_files', 0)}")
                print(f"  Lines of Code:       {stats.get('total_lines', 0)}")
                if stats.get('languages'):
                    print(f"  Languages: {', '.join(f'{k}({v})' for k, v in stats['languages'].items())}")
        
        # Generate Markdown Report
        if result.get('success', False) or result.get('status') != 'ERROR':
            from agent.tools.report_builder import format_report_as_markdown
            markdown_report = format_report_as_markdown(result)
            
            # Save to file if requested
            if args.output:
                try:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        f.write(markdown_report)
                    print(f"\nDetailed report saved to: {args.output}")
                except Exception as e:
                    print(f"Error saving report to file: {e}")
            
            # Print detailed report if requested
            if args.detailed:
                print("\n" + "="*50)
                print("DETAILED REPORT")
                print("="*50)
                print(markdown_report)
            elif result.get('findings'):
                print("\nFindings Summary (use --detailed for full report):")
                for finding in result.get('findings')[:3]:  # Show first 3
                    # Handle both formats: file_path/line_number and file/line
                    file_path = finding.get('file_path') or finding.get('file', 'Unknown')
                    line = finding.get('line_number') or finding.get('line', 0)
                    method = finding.get('method_name', finding.get('type', 'Unknown'))
                    print(f"- {file_path}:{line} ({method})")
                if len(result.get('findings')) > 3:
                    print(f"... and {len(result.get('findings')) - 3} more.")
        else:
            print("\nAnalysis failed. No report generated.")
                
    except Exception as e:
        print(f"\nError running flow: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
