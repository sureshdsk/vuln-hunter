from rest_framework import serializers
from .models import Job

class JobSerializer(serializers.ModelSerializer):
    class Meta:
        model = Job
        fields = [
            'id', 'repo_url', 'branch', 'cve_id', 
            'status', 'created_at', 'updated_at', 
            'completed_at', 'error_message'
        ]
        read_only_fields = ['id', 'status', 'created_at', 'updated_at', 'completed_at', 'error_message']
