"""
Django models for Jobs app - manages CVE analysis jobs
"""

import uuid
from django.db import models


class Job(models.Model):
    """Analysis job model"""
    
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('RUNNING', 'Running'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    repo_url = models.URLField(max_length=500)
    branch = models.CharField(max_length=255, default='main')
    cve_id = models.CharField(max_length=50)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    
    # Prefect integration
    prefect_flow_run_id = models.UUIDField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Error tracking
    error_message = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['cve_id']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"Job {self.id}: {self.cve_id} on {self.repo_url}"
