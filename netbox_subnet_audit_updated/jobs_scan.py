# jobs_scan.py

from django_rq import job
from netbox_subnet_audit_updated.models2 import SubnetAuditUpdated, AuditRecordUpdated
import subprocess
import logging
import datetime
import os
import re
import time

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

    # Update status to active
    subnet_audit.status = 'active'
    subnet_audit.save(update_fields=['status'])
    logger.info(f"Updated audit status to 'active' for ID {subnet_audit_id}. [jobs_scan.py]")

    # Default CIDR /24
    subnet_str = subnet_audit.subnet
    cidr = f"{subnet_str}/24"
    logger.info(f"Scanning subnet {cidr} for active IPs. [jobs_scan.py]")

    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    scan_py_path = os.path.join(script_dir, "scan.py")

    try:
        # Check if scan.py exists
        if os.path.exists(scan_py_path):
            logger.info(f"Found scan.py at {scan_py_path}. Running scan using scan.py")
            active_ips = run_scan_py(subnet_audit, subnet_str, scan_py_path)
        else:
            logger.warning(f"scan.py not found at {scan_py_path}. Falling back to nmap")
            active_ips = run_nmap_scan(subnet_audit, cidr)

        # Save active IPs to the database
        subnet_audit.active_ips = active_ips
        subnet_audit.save(update_fields=['active_ips'])
        logger.info(f"Scan complete for subnet {cidr}. Active IPs: {active_ips}. [jobs_scan.py]")

        # If we get here, the scan was successful - update status to finished
        subnet_audit.status = 'finished'
        subnet_audit.save(update_fields=['status'])
        logger.info(f"Updated audit status to 'finished' for ID {subnet_audit_id}. [jobs_scan.py]")

        # Trigger ping test for active IPs - this is optional as we already have rich data
        # Uncomment if you still want to run ping tests
        # from .jobs import run_ping_test
        # run_ping_test.delay(subnet_audit_id)

    except Exception as e:
        logger.error(f"Error in run_scan_job: {str(e)}. [jobs_scan.py]")

        # If there's an error, update status to failed
        subnet_audit.status = 'failed'
        subnet_audit.save(update_fields=['status'])
        logger.info(f"Updated audit status to 'failed' for ID {subnet_audit_id} due to error. [jobs_scan.py]")

        # Create an error record
        AuditRecordUpdated.objects.create(
            subnet_audit=subnet_audit,
            record=f"Scan error: {str(e)}",
            timestamp=datetime.datetime.now()
        )

def run_scan_py(subnet_audit, subnet_str, scan_py_path):
    """Run scan.py as a subprocess to scan the subnet"""
    active_ips = []
    try:
        # Run scan.py as a subprocess
        logger.info(f"Executing: python3 {scan_py_path} {subnet_str}")
        process = subprocess.Popen(
            ["python3", scan_py_path, subnet_str],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Process output line by line as it comes
        stdout_lines = []
        for line in iter(process.stdout.readline, ''):
            if not line:  # End of stream
                break

            stdout_lines.append(line)
            logger.debug(f"scan.py output: {line.strip()}")

            # Look for the specific output format we want
            # Pattern: "Finished scanning 172.17.141.5, Results: {'enterprise': 13858, ...}"
            match = re.search(r"Finished scanning ([0-9.]+), Results: ({.*})", line)
            if match:
                ip = match.group(1)
                results_str = match.group(0)

                # Add to active IPs list
                active_ips.append(ip)

                # Create an audit record with the scan results
                AuditRecordUpdated.objects.create(
                    subnet_audit=subnet_audit,
                    record=results_str,
                    timestamp=datetime.datetime.now()
                )
                logger.info(f"Added scan result for IP: {ip}")

        # Wait for process to complete with timeout
        for _ in range(30):  # Wait up to 30 seconds
            if process.poll() is not None:  # Process has terminated
                break
            time.sleep(1)
        else:
            # Process is taking too long, kill it
            process.terminate()
            logger.warning("scan.py process took too long and was terminated")

        # Check if no results were found
        if not active_ips and stdout_lines:
            logger.warning("scan.py completed but no results were parsed. Raw output:")
            for line in stdout_lines:
                logger.warning(f"  {line.strip()}")

        # If there was an error, log it
        stderr = process.stderr.read()
        if stderr:
            logger.error(f"scan.py stderr: {stderr}")

    except Exception as e:
        logger.error(f"Error running scan.py: {str(e)}")
        # Create an error record
        AuditRecordUpdated.objects.create(
            subnet_audit=subnet_audit,
            record=f"Scan error: {str(e)}",
            timestamp=datetime.datetime.now()
        )

    return active_ips

def run_nmap_scan(subnet_audit, cidr):
    """Fallback to nmap if scan.py fails"""
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
                    # Handle hostnames in parentheses like "hostname.example.com (192.168.1.1)"
                    if "(" in ip_address and ")" in ip_address:
                        ip_address = ip_address.split("(")[1].split(")")[0]
                    active_ips.append(ip_address)

                    # Create a simple result record for nmap-discovered IPs
                    # Format similar to scan.py output for consistency
                    results_str = f"Finished scanning {ip_address}, Results: {{'method': 'nmap fallback'}}"

                    # Create an audit record with the scan results
                    AuditRecordUpdated.objects.create(
                        subnet_audit=subnet_audit,
                        record=results_str,
                        timestamp=datetime.datetime.now()
                    )
                    logger.info(f"Found active IP: {ip_address}. [jobs_scan.py]")
        else:
            logger.error(f"nmap scan failed with error: {result.stderr}. [jobs_scan.py]")
            # Create an error record
            AuditRecordUpdated.objects.create(
                subnet_audit=subnet_audit,
                record=f"Scan error: nmap failed with: {result.stderr}",
                timestamp=datetime.datetime.now()
            )
    except Exception as e:
        logger.error(f"Error during nmap scan: {e}. [jobs_scan.py]")
        # Create an error record
        AuditRecordUpdated.objects.create(
            subnet_audit=subnet_audit,
            record=f"Scan error: {str(e)}",
            timestamp=datetime.datetime.now()
        )

    return active_ips