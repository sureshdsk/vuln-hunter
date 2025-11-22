"""Placeholder views for jobs app - to be implemented"""

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status


@api_view(['GET'])
def job_list(request):
    """List all jobs"""
    return Response({"message": "Job list endpoint - to be implemented"})


@api_view(['GET'])
def job_detail(request, job_id):
    """Get job details"""
    return Response({"message": f"Job {job_id} details - to be implemented"})


@api_view(['POST'])
def create_job(request):
    """Create new analysis job"""
    return Response(
        {"message": "Create job endpoint - to be implemented"},
        status=status.HTTP_201_CREATED
    )
