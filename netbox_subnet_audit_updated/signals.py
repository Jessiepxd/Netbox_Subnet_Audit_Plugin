# from django.db.models.signals import post_save
# from django.dispatch import receiver
# from django.apps import apps
# from .jobs import run_ping_test

# @receiver(post_save, sender=apps.get_model('netbox_subnet_audit_updated', 'SubnetAuditUpdated'))
# def trigger_ping_job(sender, instance, created, **kwargs):
#     if created:
#         run_ping_test.delay(instance.id)

import logging
from django.db.models.signals import post_save
from django.dispatch import receiver
from netbox_subnet_audit_updated.models2 import SubnetAuditUpdated
# from .jobs import run_ping_test
from .jobs_devices import scan_and_probe_subnet
from django.apps import apps

logger = logging.getLogger('netbox_subnet_audit_updated')

# Signal handler for creating an audit job after a new SubnetAuditUpdated is saved
@receiver(post_save, sender=apps.get_model('netbox_subnet_audit_updated', 'SubnetAuditUpdated'))
def trigger_ping_job(sender, instance, created, **kwargs):
    if created:
        try:
            logger.info(f"Enqueuing scan_and_probe_subnet job for SubnetAuditUpdated ID {instance.id}. [signals.py]")
            scan_and_probe_subnet.delay(instance.id)
        except Exception as e:
            logger.error(f"Error during job scheduling for SubnetAuditUpdated ID {instance.id}: {e}. [signals.py]")
            instance.status = 'failed'
            instance.save(update_fields=['status'])

# Explicitly connect the signal
# post_save.connect(trigger_ping_job, sender=SubnetAuditUpdated)

