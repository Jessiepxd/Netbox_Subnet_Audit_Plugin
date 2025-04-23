import socket, struct, json, time
import sys, os
sys.path.append('..')
# import asnmp, ahttp, assh, asynergy, images
# import utils
from collections import OrderedDict
# import devicelab
import asnmp
import ahttp

class Device(object):
    # Class Constants
    GROUP = None        # Device's Group name in config tree.
    WILDCARD = '*.ciu'  # Wildcard to use when asking user for firmware files.
    UNZIP = True        # If the firmware for this device is a zipfile or not
    MAX_SNMP = 1        # Maximum number of simultaneous SNMP operations.
    TIMEOUT = 4.0       # Default timeout for basic operations.
    IOCONFIGS = {}      # {name: versions} where 'name' is "INxOUT".
    COLUMNS = None      # Used only for sub-devices.
    SSH = None          # SSH configuration for this device.
    licenseoid = None   # required to upload a license
    SNMP_RETRIES = 1    # Default number of retries for SNMP operations.
    SNMP_TIMEOUT = 2.0  # Default timeout per retry of SNMP operations.

##  # Required instance attributes

##    self.host     # The IP address of the device.
##                  # FUTURE: Will accept and lookup a hostname.
##                  # Used for display only.

##    self.IP       # The IP address of the device.
##                  # Derived from self.host.
##                  # Used to uniquely identify the device.

##    self.IP32     # The 32-bit integer representation of the IP address.
##                  # Used to sort nodes.

##    self.name     # The product name. Returned by get_name() method.

##    self.icon     # The name of the icon to use when displaying
##                  # in the tree view

##    self.errors   # Empty list normally.
##                  # Will contain a list of error messages
##                  # if a probe() failed (self.ok = False)

##    self.ok       #

##    self.warnings   # Empty list normally.
##                    # Will contain a list of warnings updated when
##                    # self.probe() finishes (self.ok = True).

##    self.self.model # Is the device model which we have validated is supported
##                    # or not. We store the device class in this variable.

##    self.http_thread   # The aHTTP object

##    self.snmp_thread   # The aSNMP object

##    self.webeasy_version   # The device Webeasy version stored ('1.5')
                             # Used when pulling Webeasy version for upgrades
                             # NOTE: Full version stored in results.webeasy

##    self.https         # Does device uses https or http? <bool>

##   From the above, we populate self.results with all processed
##   information from all replies. It can contain any of the following:
##   self.results = {
##        'enterprise': int,      # From sysObjectID or SNMPv3 engineID.
##        'vendor': str,          # From 'enterprise' number, if found.
##        'netbios': str,         # Possibly from NetBIOS query.
##        'card_name': str,       # From cardName OID or WebEASY 1@s.
##        'serial': str,          # From boardSerialNumber OID or WebEasy 8@s.
##        'mac': str,             # The best-guess MAC address for this device.
##        'alias': str,           # Card alias name given by user.
##        'major': int,           # FW version softwareRevisionMajor OID or WebEasy 3@i.
##        'minor': int,           # FW version softwareRevisionMinor OID or WebEASY 4@i.
##        'build': int,           # FW version softwarePointReleaseNumber or WebEASY 6@s.
##        'board_name': str,      # boardName OID or WebEASY 9@s.
##        'board_rev': str,       # boardRevision OID or Webeasy 10@s
##        'board_build': int,     # boardBuild OID or Webeasy 11@i
##        'http_name': str,       # Best-guess name of HTTP server or `None`.
##        }

##    self.interfaces   # The IP interfaces on the device, if we can pull this.

##    self.current_firmware   # Intially set as the device's current firmware
##                            # that we found using SNMP. But a module can
##                            # overwrite this field if we have sub modules.

##   self.selected      # Determines if the device is selected for upgrade.

    def __init__(self, device_info_object: "devicelab.DeviceInfo", **kwargs):
        '''Sets device host (IP), snmp/http threads, logging destination.'''
        # self.host = host
        # Convert IP back to string representation.
        self.IP = device_info_object.IP
        self.IP32 = device_info_object.IP32
        # Set required internal attributes to defaults.
        # self.debug = int(debug)
        self.name = device_info_object.results.get('card_name', 'unknown')
        self.icon = device_info_object.icon          # Case-sensitive
        self.ok = False                 # True if refresh succeeded.
        self.model = device_info_object.model               # Reserved for discovery.
        self.http_thread = device_info_object.http_thread
        self.snmp_thread = device_info_object.snmp_thread
        self.webeasy_version = device_info_object.results.get('http_name')
        self.nbt_thread = device_info_object.nbt_thread
        self.https = device_info_object.https              # If device uses https
        self.results = device_info_object.results
        self.snmp = device_info_object.snmp
        self.interfaces = device_info_object.interfaces
        self.current_firmware = device_info_object.current_firmware
        self.selected = True         # Checkboxes. If its selected or not
        # self.device_supported = 'X'                        # Can the device upgrade
        self.errors = []
        self.warnings = []
        self.requests = {}                                 # Ongoing operations as { name: op }.
        self.started = False                               # Operation start timestamp.
        self.flags = {
            'uploadFinished': False, 'upgradeFinished': False,
            'upgradeError': False, 'upgradeActive': False,
            'rebooting': False,
        }
        # Set reserved attributes for compatibility.

    def probe(self):
        '''
        Start a probe of the device at self.IP.
        Start whatever operations are required to find:
            ProductType, Features, Alias, SerialNumber, FirmwareVersion
        Must be able to detect if accessing wrong card.
        Does not block. Returns right away.
        '''
        # Don't start probe if busy (start timestamp set).
        if self.started:
            return
        self.started = time.time()
        self.ok = False
        self.errors = []
        self.warnings = []

    def restart_snmp_threads(self):
        """
            This method is used to restart the SNMP threads.
            The SNMP threads usually die when passed through the objects so
            before the upgrade we will check and instantiate them
        """
        if not self.snmp_thread.is_alive() or not self.http_thread.is_alive():
            self.snmp_thread = asnmp.start()
            self.http_thread = ahttp.start()

    def login(self):
        """This method is used to login to the device. Using Webeasy"""
        data = {'user': 'root', 'password': 'evertz', 'SubmitPassword': 'Login'}
        return self.http_thread.post(
            'http://' + self.IP + '/login.php', data=data, block=False)

    def validate_license(self, results: dict, license_filepath: str):
        """
            This method is used to validate if the license file passed in
            has the correct name, mac and serial number of the device which
            they are trying to upgrade from.
            The license filename format should be:
                PRODUCTNAME - MM - DD - YYYY - HH - MM - SS - MAC_UNDERSCORE_SEPARATED - SIZE
            ex. CBS-570IPG-X19-10G-05-04-2023-15-09-26-3c_e0_64_24_5f_ce-small.key

            Step 1: Validate that there is a license in the file
            Step 2: Validate that the name is in the right format

            Parameters:
                results: a dictionary of all of the results of the object. <dict>
                    ex: {card_name:'Scorpion-6', sysDescr:'scorpion6', mac:, serial:}
                license_filepath: Needs to be in the format defined above. A string <str>

            Raises ValueError if validation fails.
            returns (size, date) if validation passes.
        """
        # Step 1: Validate that there is a license in the file
        # Open the file
        try:
            f = open(license_filepath, 'r')
            content = f.read()
            if content:
                # Validate that '"license":' is in the file.
                if '"license":' not in content:
                    raise FileNotFoundError("ERROR: There was a problem"
                                            "validating file: "
                                            f"{license_filepath}. License "
                                            "was not found in the dictionary. "
                                            f"File contents: {content}")
        except Exception as error:
            print("ERROR: There was a problem"
                  f"locating file: {license_filepath}. error: {error}")

        # Step 2: Validate that the name is in the right format
        # Create the expected license filename
        # expected_mac: '0002C5331342'
        expected_mac = results.get('mac').replace(':', '').replace('-', '')
        # card_name: 'SCORPION-6F'
        card_name = self.name
        size = ""
        date = ""
        # Remove all dashes and underscores. Then validate mac address
        raw_string = license_filepath.replace('_', '').replace('-', '')
        # Validate that the license is in the correct format
        if not expected_mac or expected_mac not in raw_string:
            raise ValueError("There was a problem Validating the license. "
                             f"The Mac address found is {expected_mac}"
                             f"missing the mac address in the filename"
                             f" {license_filepath}")
        if not card_name or card_name not in license_filepath:
            raise ValueError("There was a problem Validating the license. "
                             f"Card Name '{card_name}' is Missing from "
                             f"the license name '{license_filepath}'")
        # Determine the size of the key
        if 'small' in license_filepath.lower():
            size = 'small'
        elif 'medium' in license_filepath.lower():
            size = 'medium'
        elif 'large' in license_filepath.lower():
            size = 'large'
        else:
            raise ValueError(("There was a problem Validating the license. "
                              "License size (small, medium or large) is "
                              "Missing from the license name "
                              f"'{license_filepath}'"))
        # Determine the date from the file
        split_name = license_filepath.split('-')
        # # remove the size and mac address
        split_name.pop()
        split_name.pop()
        # Save the date (dd-mm-yyyy-hour-minute-second)
        day = split_name[-6]
        month = split_name[-5]
        year = split_name[-4]
        hour = split_name[-3]
        minute = split_name[-2]
        second = split_name[-1]
        # Combine the date.
        date = " ".join([day, month, year, hour, minute, second])
        return (size, date)

        # # The license name is an expected name. Set the flag that we have a valid license
        # return True

    def validate_upgrade_firmware(self, filepath):
        """ This method will be called when the user supplies a firmware in the upgrade
            dialog. This method is used to determine if the firmware is supported on the
            model specified

            Example:
            This method will take apart the tar.gz file passed and will check
            what device is supported.
            1. Open the tar.gz file
            2. Check that all of the files needed are present.
                (checksum.md5, firmware.img, prod.regex and version.)
            3. Check that checksome contains a file inside called 'firmware.img'
            4. Check that the prod.regex file has 'SCORPION' as the only field inside
            5. Check that the version file has a proper version inside the file.?

            this method will set the self.upgrade_file field to contain the tar
            returns a touple (supported, firmware_device, firmware_version)
            ex:
                supported: True if supported, raises valueError if not supported
                firmware_device: 'SCORPION-6'
                firmware_version: 'Version 1.0 build 137'
        """
        raise NotImplementedError

    def validate_firmware(self, image_dict, filename):
        '''
        Checks the 'image_dict' and its originating 'filename'
        (stripped of path) for suitability as an upgrade image.

        The image_dict is a dictionary of { filename: binary_blob }.
        If self.UNZIP is True, an image that is a zipfile will be
        decompressed into multiple items.
        Will raise ValueError if the image is not suitable in any way.
        Returns an authoritative version string of the 'image' upon success.
        '''
        raise NotImplementedError

    def pull_firmware(self):
        """ A method to pull the firmware of the device using its varid.
            Usually used to make sure that the firmware is the same before
            and after upgrades.

            This method should return the current current firmware
            """
        raise NotImplementedError

    def upgrade(self, filepath):
        '''
        Initiates an upgrade of the device using
        self.firmware: The data inside of the file. (opened/.read())

        Attempts to assign firmware to the card using an authoritative
        'version' string. 'filepath' is the file location of the
        firmware required to upgrade. This method should populate self.firmware.

        This method should also Validate if the device firmware changed by
        using 'pull_firmware' method to pull the firmware of the device.

        Usually we need to restart the SNMP threads and login to the device
        to save our cookie.

        Parameters:
            filepath: The path to the upgrade firmware file. (.ciu, .tar,
                .app) file. This file should instantiate self.firmware

        '''
        raise NotImplementedError

    def upload_license(self, filepath):
        """
            Uploads the license file to the device specified.

            Parameters:
                filepath: The path to the license file

            updates the same flags as upgrade():
                upgradeFinished: Boolean if the upload/upgrade is finished <bool>
                upgradeError: The explanation as to why the upgrade failed <str>

        """
        # Restart SNMP & HTTP threads
        self.restart_snmp_threads()
        # login to the device
        self.login()
        # Open the license file
        try:
            f = open(filepath, 'r')
            license_file = f.read()
            f.close()
        except ValueError as error:
            raise ValueError("There was a problem reading the license file"
                             f"path: {filepath}. Error: {error}")
        # Check the http type
        str_https = 'http'
        if self.https:
            str_https = 'https'
        # Get the filename
        filename = filepath.split("\\")[-1]
        # progress_dialog.Update(10, "Start the license upload...")
        # Send the first
        # POST /v.1.5/php/features/feature-transfer-upload.php?filename=license.txt HTTP/1.1
        command = (f'{str_https}://{self.IP}/{self.webeasy_version}/php/features/' +
                   f'feature-transfer-upload.php?filename={filename}')
        print(f"Sending the upgrade file '{filename}' to the device using " +
              f"POST command {command}.")
        headers = {'Content-Type': 'multipart/form-data'}
        data = license_file
        op = self.http_thread.post(command, data=data, headers=headers, timeout=60)
        # progress_dialog.Update(60, "Finished the license upload...")
        # Validate that the reply is in this format
        try:
            content = op.content.decode('utf-8')
        except Exception as error:
            print(f"ERROR: {error}")
            raise ValueError(error)
        print(f"DEBUG: UploadFile command: {command}, op.error:{op.error}, content:{content}")
        # Reply should be 'Completed Upload - /tmp/upgrade-files/SCORPION-6.tar.gz size:70667019--existing:1\n'
        if (op.finished and (not op.ok or op.error or 'Completed Upload' not in content)):
            comment = ("There was a problem uploading the file " +
                       f"{filename}, ok:{op.ok}, content:{content}")
            self.flags['upgradeError'] = comment
            # progress_dialog.Update(90, comment)
            # raise ValueError(comment)

        # Completed the upload. Now try to import the license.
        # GET /v.1.5/php/features/feature-transfer-import.php?action=import_license&varid=9152.0@f&filename=license.txt&slot=0 HTTP/1.1
        op = self.http_thread.get((f'{str_https}://{self.IP}/' +
                                   f'{self.webeasy_version}/php/features/' +
                                   'feature-transfer-import.php?' +
                                   'action=import_license&varid=9152.0@f' +
                                   f'&filename={filename}&slot=0'))
        # Validate that the value is the expected value
        content = op.content.decode('utf-8')
        if (op.finished and (not op.ok or op.error or 'Success' not in content)):
            # self.flags['upgradeError'] = True
            comment = ("There was a problem importing the file " +
                       f"{filename}, ok:{op.ok}, content:{content}")
            self.flags['upgradeError'] = comment
            # progress_dialog.Update(90, comment)
            # raise ValueError(comment)
        # progress_dialog.Update(90, "Finished the license import.")
        self.flags['upgradeFinished'] = True
#end class Device(object)
