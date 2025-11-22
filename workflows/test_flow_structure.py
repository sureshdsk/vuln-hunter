"""
Test script for CVE Analysis Workflow
"""

import os
import sys
from unittest.mock import MagicMock, patch

# Add the workflows directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Mock Prefect tasks to avoid actual execution during import test
with patch("prefect.task", side_effect=lambda f=None, **kwargs: f if f else lambda x: x):
    with patch("prefect.flow", side_effect=lambda f=None, **kwargs: f if f else lambda x: x):
        from flows.cve_analysis_flow import analyze_repository_for_cve

def test_flow_structure():
    """Test that the flow imports correctly and has the expected structure"""
    print("Successfully imported analyze_repository_for_cve flow")
    
    # Verify it's a function (since we mocked the flow decorator)
    assert callable(analyze_repository_for_cve)
    print("Flow is callable")

if __name__ == "__main__":
    try:
        test_flow_structure()
        print("Verification successful!")
    except Exception as e:
        print(f"Verification failed: {e}")
        sys.exit(1)
