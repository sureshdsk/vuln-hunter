"""
Django models for Reports app - manages vulnerability reports and findings
"""

from django.db import models
from jobs.models import Job


class VulnerabilityReport(models.Model):
    """Vulnerability analysis report model"""
    
    STATUS_CHOICES = [
        ('VULNERABLE', 'Vulnerable'),
        ('NOT_VULNERABLE', 'Not Vulnerable'),
        ('UNKNOWN', 'Unknown'),
    ]
    
    job = models.OneToOneField(Job, on_delete=models.CASCADE, related_name='report')
    cve_id = models.CharField(max_length=50)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    summary = models.TextField(blank=True)
    
    # Report formats
    report_html = models.TextField(blank=True)
    report_json = models.JSONField(default=dict)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Report for Job {self.job.id}: {self.status}"


class Finding(models.Model):
    """Individual vulnerability finding in code"""
    
    report = models.ForeignKey(
        VulnerabilityReport,
        on_delete=models.CASCADE,
        related_name='findings'
    )
    
    file_path = models.CharField(max_length=500)
    line_number = models.IntegerField()
    method_name = models.CharField(max_length=255)
    
    exploitable = models.BooleanField(default=False)
    confidence = models.FloatField(help_text="Confidence score between 0 and 1")
    
    explanation = models.TextField()
    suggested_fix = models.TextField()
    code_snippet = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-confidence', 'file_path', 'line_number']
    
    def __str__(self):
        return f"Finding in {self.file_path}:{self.line_number}"


class Recommendation(models.Model):
    """Report recommendations"""
    
    report = models.ForeignKey(
        VulnerabilityReport,
        on_delete=models.CASCADE,
        related_name='recommendations'
    )
    
    text = models.TextField()
    priority = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-priority']
    
    def __str__(self):
        return f"Recommendation for {self.report.job.id}"
