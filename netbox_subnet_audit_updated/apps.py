from django.apps import AppConfig
import logging

class NetBoxSubnetAuditUpdatedConfig(AppConfig):
    name = 'netbox_subnet_audit_updated'
    verbose_name = 'NetBox Subnet Audit Updated'

    def ready(self):
        # Log that the ready function is being called
        logger = logging.getLogger('netbox_subnet_audit_updated')
        logger.info("NetBoxSubnetAuditUpdatedConfig.ready() called, importing signals.")

        # Import signals to ensure they are registered
        import netbox_subnet_audit_updated.signals
