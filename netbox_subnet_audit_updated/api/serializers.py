from rest_framework import serializers
from netbox.api.serializers import NetBoxModelSerializer
from ..models2 import SubnetAuditUpdated, AuditRecordUpdated

class AuditRecordSerializer(NetBoxModelSerializer):
    class Meta:
        model = AuditRecordUpdated
        fields = ['id', 'subnet_audit', 'record', 'timestamp']

class SubnetAuditUpdatedSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_subnet_audit_updated-api:subnetauditupdated-detail'
    )

    audit_records = AuditRecordSerializer(many=True, read_only=True)

    class Meta:
        model = SubnetAuditUpdated
        fields = ['id', 'subnet', 'status', 'time_created', 'audit_records']
