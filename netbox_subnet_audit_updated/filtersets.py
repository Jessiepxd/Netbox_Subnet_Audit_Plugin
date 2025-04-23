from netbox.filtersets import NetBoxModelFilterSet
from .models2 import SubnetAuditUpdated

class SubnetAuditUpdatedFilterSet(NetBoxModelFilterSet):
    class Meta:
        model = SubnetAuditUpdated
        fields = ('id', 'subnet', 'status')

    def search(self, queryset, name, value):
        return queryset.filter(subnet__icontains=value)
