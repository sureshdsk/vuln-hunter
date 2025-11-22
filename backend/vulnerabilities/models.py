"""
Django models for Vulnerabilities app - CVE information from databases
"""

from django.db import models


class CVEInfo(models.Model):
    """CVE information from vulnerability databases"""
    
    cve_id = models.CharField(max_length=50, primary_key=True)
    summary = models.TextField()
    
    severity = models.CharField(max_length=20, blank=True)
    cvss_score = models.FloatField(null=True, blank=True)
    
    # JSON fields for complex data
    affected_packages = models.JSONField(default=list)
    vulnerable_methods = models.JSONField(default=list)
    references = models.JSONField(default=list)
    metadata = models.JSONField(default=dict)
    
    # Source tracking
    source = models.CharField(max_length=50, default='OSV')  # OSV, NVD, Vulners, etc.
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "CVE Information"
        verbose_name_plural = "CVE Information"
        ordering = ['-last_updated']
    
    def __str__(self):
        return f"{self.cve_id}: {self.summary[:50]}"
