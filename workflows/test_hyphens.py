
from agent.tools.cve_lookup import cve_lookup_tool

def test_hyphens():
    # The user's input (copied from their message)
    bad_cve = "CVE‑2022‑34757" 
    
    # Standard format
    good_cve = "CVE-2022-34757"
    
    print(f"Bad CVE hex: {bad_cve.encode('utf-8').hex()}")
    print(f"Good CVE hex: {good_cve.encode('utf-8').hex()}")
    
    if bad_cve != good_cve:
        print("Confirmed: Strings are different!")
    else:
        print("Strings are identical.")

    print("\nLookup with Bad CVE:")
    result = cve_lookup_tool(bad_cve)
    print(result.get("error"))

if __name__ == "__main__":
    test_hyphens()
