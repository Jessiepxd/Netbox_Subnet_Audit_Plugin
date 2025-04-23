# jobs_scan.py

from django_rq import job
from netbox_subnet_audit_updated.models2 import SubnetAuditUpdated
import subprocess
import logging
from ipaddress import ip_network

logger = logging.getLogger('netbox_subnet_audit_updated')

@job('default')
def run_scan_job(subnet_audit_id):
    logger.info(f"Starting run_scan_job for SubnetAuditUpdated ID {subnet_audit_id}. [jobs_scan.py]")

    try:
        # Fetch the SubnetAuditUpdated instance
        subnet_audit = SubnetAuditUpdated.objects.get(id=subnet_audit_id)
    except SubnetAuditUpdated.DoesNotExist:
        logger.error(f"SubnetAuditUpdated with ID {subnet_audit_id} does not exist. [jobs_scan.py]")
        return

    # Default CIDR /24
    cidr = f"{subnet_audit.subnet}/24"
    logger.info(f"Scanning subnet {cidr} for active IPs using nmap. [jobs_scan.py]")

    active_ips = []
    try:
        # Run nmap command
        result = subprocess.run(
            ['nmap', '-sn', '-T4', cidr],
            capture_output=True,
            text=True
        )

        # Check if nmap executed successfully
        if result.returncode == 0:
            # Parse the nmap output for active hosts
            for line in result.stdout.splitlines():
                if "Nmap scan report for" in line:
                    ip_address = line.split()[-1]
                    active_ips.append(ip_address)
                    logger.info(f"Found active IP: {ip_address}. [jobs_scan.py]")
        else:
            logger.error(f"nmap scan failed with error: {result.stderr}. [jobs_scan.py]")
    except Exception as e:
        logger.error(f"Error during nmap scan: {e}. [jobs_scan.py]")

    # Save active IPs to the database
    subnet_audit.active_ips = active_ips
    subnet_audit.save(update_fields=['active_ips'])
    logger.info(f"Scan complete for subnet {cidr}. Active IPs: {active_ips}. [jobs_scan.py]")

    # Trigger ping test for active IPs
    from .jobs import run_ping_test
    run_ping_test.delay(subnet_audit_id)
