import logging
from django.db import models
import netbox.models
from utilities.choices import ChoiceSet
from django.urls import reverse
from rq.job import Job
from django_rq import get_queue
from django.urls import reverse
import os
from django.conf import settings  # Import settings to access AUTH_USER_MODEL
from datetime import timedelta
import time
from django.contrib.postgres.fields import ArrayField

# from . import signals

logger = logging.getLogger('netbox_subnet_audit_updated')

class SubnetAuditStatusChoicesUpdated(ChoiceSet):
    key = 'SubnetAudit.status'

    CHOICES = [
        ('queued', 'Queued'),
        ('active', 'Active'),
        ('deferred', 'Deferred'),
        ('finished', 'Finished'),
        ('failed', 'Failed'),
    ]

class SubnetAuditUpdated(netbox.models.NetBoxModel):
    subnet = models.GenericIPAddressField(protocol='both', unpack_ipv4=False)
    active_ips = models.JSONField(default=list)
    status = models.CharField(max_length=30, choices=SubnetAuditStatusChoicesUpdated.CHOICES, default='queued')
    time_created = models.DateTimeField(auto_now_add=True)
    job_id = models.CharField(max_length=255, null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,  # Use AUTH_USER_MODEL to ensure compatibility
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="subnet_audits",
    )


    class Meta:
        ordering = ('-time_created',)

    def __str__(self):
        return f"{self.subnet} - {self.status} - {self.time_created}"

    def get_absolute_url(self):
        return reverse('plugins:netbox_subnet_audit_updated:subnetauditupdated', args=[self.pk])

    def save(self, *args, **kwargs):
        is_new = self.pk is None
        user = kwargs.pop('user', None)  # Safely pop user without error

        if is_new and user:  # Set `created_by` only for new instances
            self.created_by = user
            logger.info(f"Assigned created_by to self.created_by.username: {self.created_by.username}), for new SubnetAuditUpdated. [models2.py]")

        # Call super to save the instance
        super().save(*args, **kwargs)

        if is_new:  # Trigger jobs only for new instances
            try:
                from .jobs_scan import run_scan_job
                from .jobs import run_ping_test
                # logger.info(f"Delaying before enqueuing the job for SubnetAuditUpdated ID {self.id}")
                # time.sleep(10)

                # Enqueue the scanning job and save job_id
                scan_job = run_scan_job.delay(self.id)
                self.job_id = scan_job.id
                self.status = 'queued'
                self.save(update_fields=['job_id', 'status'])
                logger.info(f"Enqueued scan job for SubnetAuditUpdated ID {self.id}, job ID {scan_job.id}. [models2.py]")

            except Exception as e:
                logger.error(f"Error during job scheduling for SubnetAuditUpdated ID {self.id}: {e}. [models2.py]")
                self.status = 'failed'
                self.save(update_fields=['status'])  # Mark as failed if job scheduling fails

class AuditRecordUpdated(netbox.models.NetBoxModel):
    # This is the SubnetAudit model to which we belong.
    subnet_audit = models.ForeignKey(
        SubnetAuditUpdated,
        on_delete=models.CASCADE,
        related_name='audit_records'
    )
    # ip = models.GenericIPAddressField(protocol='both', unpack_ipv4=False)
    # A simple line of text (for now) that describes what we found at this IP.
    record = models.TextField()
    # The date in which this scan result was obtained.
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-timestamp',)

    def __str__(self):
        return f"Record for {self.subnet_audit.subnet} at {self.timestamp}. [models2.py]"