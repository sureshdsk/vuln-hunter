"""URL patterns for jobs app"""

from django.urls import path
from . import views

urlpatterns = [
    path('', views.job_list, name='job-list'),
    path('<uuid:job_id>/', views.job_detail, name='job-detail'),
    path('create/', views.create_job, name='job-create'),
]
