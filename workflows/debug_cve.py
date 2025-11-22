
import sys
import os

# Add workflows to path
sys.path.append(os.getcwd())

from agent.tools.cve_lookup import cve_lookup_tool
from agent.tools.dependency_check import dependency_check_tool

def debug():
    cve_id = "CVE-2022-34757"
    print(f"Fetching data for {cve_id}...")
    cve_info = cve_lookup_tool(cve_id)
    
    print("\nCVE Info:")
    print(f"Summary: {cve_info.get('summary')}")
    print(f"Affected Packages: {cve_info.get('affected_packages')}")
    
    print("\nTesting Dependency Check...")
    
    # Mock code index with Django 1.8.1
    mock_index = {
        "files": {
            "requirements.txt": {
                "content": "Django==1.8.1\nrequests==2.25.1"
            }
        }
    }
    
    findings = dependency_check_tool(mock_index, cve_info)
    print("\nFindings:")
    print(findings)

    print("\nChecking NVD API...")
    import requests
    try:
        r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
        if r.status_code == 200:
            data = r.json()
            if data.get("vulnerabilities"):
                vuln = data["vulnerabilities"][0]["cve"]
                print(f"Summary: {vuln.get('descriptions', [{}])[0].get('value')}")
                print(f"Metrics: {vuln.get('metrics')}")
            else:
                print("No vulnerabilities found in NVD response")
        else:
            print(f"Failed: {r.status_code}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    debug()
