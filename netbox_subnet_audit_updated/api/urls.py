from netbox.api.routers import NetBoxRouter
from . import views

app_name = 'netbox_subnet_audit_updated'

router = NetBoxRouter()
router.register('subnet-audits', views.SubnetAuditUpdatedViewSet)

urlpatterns = router.urls