"""Views for jobs app"""

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from .models import Job
from .serializers import JobSerializer


@api_view(['GET'])
def job_list(request):
    """List all jobs"""
    jobs = Job.objects.all()
    serializer = JobSerializer(jobs, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def job_detail(request, job_id):
    """Get job details"""
    job = get_object_or_404(Job, id=job_id)
    serializer = JobSerializer(job)
    return Response(serializer.data)


@api_view(['POST'])
def create_job(request):
    """Create new analysis job"""
    serializer = JobSerializer(data=request.data)
    if serializer.is_valid():
        job = serializer.save()
        # TODO: Trigger Prefect flow here
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
