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

from flows.cve_analysis_flow import analyze_repository_for_cve

import argparse

def main():
    parser = argparse.ArgumentParser(description="Run CVE analysis on a repository")
    parser.add_argument("--repo", default="https://github.com/sureshdsk/basic-auth-django", help="Repository URL")
    parser.add_argument("--branch", default="master", help="Branch to analyze")
    parser.add_argument("--cve", default="CVE-2025-64458", help="CVE ID to check")
    parser.add_argument("--detailed", action="store_true", help="Print detailed markdown report to console")
    parser.add_argument("--output", help="Save report to file (e.g., report.md)")
    
    args = parser.parse_args()
    
    # Configuration
    repo_url = args.repo
    branch = args.branch
    cve_id = args.cve
    job_id = str(uuid.uuid4())
    
    print(f"Starting analysis job {job_id}")
    print(f"Repo: {repo_url}")
    print(f"Branch: {branch}")
    print(f"CVE: {cve_id}")
    
    # Check for API Key
    if not os.getenv("GOOGLE_API_KEY"):
        print("WARNING: GOOGLE_API_KEY not found in environment.")
        print("The AI agent analysis might fail or return limited results.")
        # You might want to uncomment this to enforce the key
        # sys.exit(1)

    try:
        result = analyze_repository_for_cve(
            job_id=job_id,
            repo_url=repo_url,
            branch=branch,
            cve_id=cve_id
        )
        
        print("\n" + "="*50)
        print("Analysis Result:")
        print("="*50)
        print(f"Status: {result.get('status')}")
        if result.get('status') == 'ERROR':
            print(f"Error: {result.get('error')}")
            
        print(f"Total Findings: {result.get('total_findings', 0)}")
        print(f"Exploitable Findings: {result.get('exploitable_findings', 0)}")
        
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
                    print(f"- {finding.get('file_path')}:{finding.get('line_number')} ({finding.get('method_name')})")
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
