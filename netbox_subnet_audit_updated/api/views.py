from netbox.api.viewsets import NetBoxModelViewSet
from .. import filtersets
from netbox_subnet_audit_updated import models2 as models  # Explicitly rename

from .serializers import SubnetAuditUpdatedSerializer

class SubnetAuditUpdatedViewSet(NetBoxModelViewSet):
    queryset = models.SubnetAuditUpdated.objects.all()
    serializer_class = SubnetAuditUpdatedSerializer
    filterset_class = filtersets.SubnetAuditUpdatedFilterSet