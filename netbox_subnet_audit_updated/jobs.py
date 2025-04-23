# jobs.py

from django_rq import job
from netbox_subnet_audit_updated.models2 import SubnetAuditUpdated, AuditRecordUpdated
import subprocess
import datetime
import logging
import os
from netbox_subnet_audit_updated import models2 as models  # Explicitly rename


logger = logging.getLogger('netbox_subnet_audit_updated')

@job('default')
def run_ping_test(subnet_audit_id):
    logger.info(f"Starting run_ping_test for SubnetAuditUpdated ID {subnet_audit_id}. [jobs.py]")

    try:
        # Fetch the SubnetAuditUpdated instance
        subnet_audit = SubnetAuditUpdated.objects.get(id=subnet_audit_id)
    except SubnetAuditUpdated.DoesNotExist:
        logger.error(f"SubnetAuditUpdated instance with ID {subnet_audit_id} does not exist. [jobs.py]")
        return

    if not subnet_audit.active_ips:
        logger.info(f"No active IPs to ping for SubnetAuditUpdated ID {subnet_audit_id}. [jobs.py]")
        subnet_audit.status = 'finished'
        subnet_audit.save(update_fields=['status'])
        return

    # Update status to active
    subnet_audit.status = 'active'
    subnet_audit.save(update_fields=['status'])

    # Ping the active IPs
    for ip in subnet_audit.active_ips:
        try:
            ip = ip.strip("()")
            logger.info(f"Running command: ping -c 1 -W 1 {ip}. [jobs.py]")
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', str(ip)],
                capture_output=True,
                text=True
            )
            logger.info(f"Return code: {result.returncode}, stdout: {result.stdout}, stderr: {result.stderr}. [jobs.py]")

            # if result.returncode == 0:
            #     record = f"Ping to {ip}: Success - {result.stdout}"
            # else:
            #     record = f"Ping to {ip}: Failure - {result.stderr}"

            # Save the ping result
            AuditRecordUpdated.objects.create(
                subnet_audit=subnet_audit,
                record=record,
                timestamp=datetime.datetime.now()
            )
            logger.info(f"Ping to {ip}: {'Success' if result.returncode == 0 else 'Failure'}. [jobs.py]")

        except Exception as e:
            # error_message = f"Ping to {ip}: Error - {str(e)}"
            AuditRecordUpdated.objects.create(
                subnet_audit=subnet_audit,
                record=error_message,
                timestamp=datetime.datetime.now()
            )
            logger.error(f"Error pinging IP {ip}: {e}. [jobs.py]")

    # Update the status to finished
    subnet_audit.status = 'finished'
    subnet_audit.save(update_fields=['status'])
    logger.info(f"Ping test completed for SubnetAuditUpdated ID {subnet_audit_id}. [jobs.py]")
