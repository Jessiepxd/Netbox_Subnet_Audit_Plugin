from netbox.plugins import PluginConfig

class NetBoxSubnetAuditUpdatedConfig(PluginConfig):
    name = 'netbox_subnet_audit_updated'
    verbose_name = 'NetBox Subnet Audit Updated'
    description = 'Audit subnets within NetBox'
    version = '0.1'
    base_url = 'subnet-audit-updated'
    # menu_items = 'netbox_subnet_audit_updated.menu_items'

config = NetBoxSubnetAuditUpdatedConfig
# default_app_config = 'netbox_subnet_audit_updated.NetBoxSubnetAuditUpdatedConfig'
# default_app_config = 'netbox_subnet_audit_updated.apps.NetBoxSubnetAuditUpdatedConfig' #Django will now use apps.py automatically, which ensures the signals are loaded properly.

