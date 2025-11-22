"""
URL configuration for vuln_hunter project.
"""

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/', include([
        path('jobs/', include('jobs.urls')),
        path('reports/', include('reports.urls')),
        path('vulnerabilities/', include('vulnerabilities.urls')),
    ])),
]
