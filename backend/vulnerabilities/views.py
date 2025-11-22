"""Placeholder views for vulnerabilities app"""

from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(['GET'])
def cve_detail(request, cve_id):
    """Get CVE information"""
    return Response({"message": f"CVE {cve_id} info - to be implemented"})
