"""Placeholder views for reports app"""

from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(['GET'])
def report_detail(request, job_id):
    """Get report for job"""
    return Response({"message": f"Report for job {job_id} - to be implemented"})


@api_view(['GET'])
def report_html(request, job_id):
    """Get HTML report"""
    return Response({"message": "HTML report - to be implemented"})


@api_view(['GET'])
def report_json(request, job_id):
    """Get JSON report"""
    return Response({"message": "JSON report - to be implemented"})
