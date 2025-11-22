"""URL patterns for vulnerabilities app"""

from django.urls import path
from . import views

urlpatterns = [
    path('<str:cve_id>/', views.cve_detail, name='cve-detail'),
]
