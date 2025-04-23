import django_tables2 as tables
from netbox.tables import NetBoxTable, ChoiceFieldColumn
from .models2 import SubnetAuditUpdated

class SubnetAuditUpdatedTable(NetBoxTable):
    id = tables.Column(linkify=True, verbose_name="ID")
    subnet = tables.Column(linkify=True)
    status = ChoiceFieldColumn()
    # created_by = tables.Column(accessor='created_by.username', verbose_name='Created By', default='Unknownintables')
    created_by = tables.Column(accessor='created_by.username', verbose_name='Created By')

    class Meta(NetBoxTable.Meta):
        model = SubnetAuditUpdated
        fields = ('id', 'pk', 'id', 'subnet', 'status', 'time_created', 'created_by', 'actions')
        default_columns = ('id', 'subnet', 'status', 'time_created', 'created_by')