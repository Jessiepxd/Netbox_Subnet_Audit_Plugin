from django.urls import path
from . import views, models2
from netbox.views.generic import ObjectChangeLogView

from .api import urls as api_urls

app_name = 'netbox_subnet_audit_updated'

urlpatterns = [
    path('', views.SubnetAuditUpdatedListView.as_view(), name='subnetauditupdated_list'),
    path('add/', views.SubnetAuditUpdatedEditView.as_view(), name='subnetauditupdated_add'),
    path('<int:pk>/', views.SubnetAuditUpdatedView.as_view(), name='subnetauditupdated'),
    path('<int:pk>/edit/', views.SubnetAuditUpdatedEditView.as_view(), name='subnetauditupdated_edit'),
    path('<int:pk>/delete/', views.SubnetAuditUpdatedDeleteView.as_view(), name='subnetauditupdated_delete'),
    path('<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='subnetauditupdated_changelog', kwargs={'model': models2.SubnetAuditUpdated}),
    path('<int:pk>/check-status/', views.check_job_status, name='check_job_status'),

]
