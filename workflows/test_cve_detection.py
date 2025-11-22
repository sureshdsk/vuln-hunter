"""
Diagnostic script to understand why CVE is not being detected
"""

print("=== CVE Detection Diagnostic ===\n")

# Check what CVE data looks like
print("1. Checking CVE lookup...")
try:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(__file__))

    # We can't import agent due to dependencies, so let's check the flow
    print("   ✓ Path configured")
except Exception as e:
    print(f"   ✗ Error: {e}")

# Check if Tree-sitter found anything
print("\n2. Checking Tree-sitter patterns...")
try:
    from code_search import VulnerabilityPatterns

    patterns = VulnerabilityPatterns.get_patterns_for_language('python')
    print(f"   ✓ Found {len(patterns)} vulnerability patterns for Python")

    # Show pattern names
    print("\n   Available patterns:")
    for p in patterns[:10]:
        print(f"     - {p.name} ({p.severity}) - {p.cwe}")

    if len(patterns) > 10:
        print(f"     ... and {len(patterns) - 10} more")

except Exception as e:
    print(f"   ✗ Error: {e}")

# Check Django version detection
print("\n3. Checking Django version detection strategy...")
print("   The CVE CVE-2025-64458 affects Django.")
print("   Current detection approaches:")
print("     1. Tree-sitter pre-scan: Looks for code patterns")
print("     2. AI Agent: Uses CVE description to find vulnerable code")
print("     3. Component usage: Checks if Django is imported")

# Suggest improvements
print("\n4. Why the CVE might not be detected:")
print("   ✗ CVE-2025-64458 might be too new for vulnerability databases")
print("   ✗ Tree-sitter patterns are generic (not CVE-specific)")
print("   ✗ AI agent needs good CVE description to correlate with code")
print("   ✗ Need dependency analysis (requirements.txt parsing)")

print("\n5. Recommendations for better CVE detection:")
print("   ✓ Parse requirements.txt/setup.py for package versions")
print("   ✓ Compare installed versions against CVE affected versions")
print("   ✓ Enhance CVE context enrichment with package matching")
print("   ✓ Add version-specific vulnerability patterns")

# Check what was scanned
print("\n6. Analysis Results Summary:")
print("   From your last run:")
print("     - Status: POTENTIALLY_VULNERABLE")
print("     - Total Findings: 3")
print("     - Files Scanned: 15")
print("     - Tree-sitter Findings: 0")
print("     - Pre-scan Findings: 0")
print("     - AI Agent Findings: 3")

print("\n7. What the AI agent found:")
print("   The AI agent found 3 potential vulnerabilities.")
print("   These might be generic issues, not specifically CVE-2025-64458")

print("\n=== Next Steps ===")
print("\n1. Check if requirements.txt has Django version:")
print("   cat <repo>/requirements.txt | grep -i django")

print("\n2. Manually verify CVE details:")
print("   Visit: https://nvd.nist.gov/vuln/detail/CVE-2025-64458")

print("\n3. Add dependency scanning:")
print("   We can enhance the tool to parse requirements.txt")
print("   and match against CVE affected package versions")

print("\n4. Review AI agent findings:")
print("   Run with --detailed --output report.md to see what was found")
