"""URL patterns for reports app"""

from django.urls import path
from . import views

urlpatterns = [
    path('<uuid:job_id>/', views.report_detail, name='report-detail'),
    path('<uuid:job_id>/html/', views.report_html, name='report-html'),
    path('<uuid:job_id>/json/', views.report_json, name='report-json'),
]
