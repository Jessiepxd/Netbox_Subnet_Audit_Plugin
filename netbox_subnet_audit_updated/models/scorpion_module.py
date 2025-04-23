import time
import tarfile
import re
import os
import copy
from models.scorpion import Scorpion

class ScorpionModule(Scorpion):
    """
        This class is created to store Scorpion Frame objects.
        This class has methods to:
            'upgrade' Method, will upgrade the scorpion Frames.
            'reboot' method will reboot the card
            'login' method will login to the device's webeasy page.
            'validate_upgrade_firmware' method will validate that the firmware
                file passed has all of the required files needed to upgrade
                properly.
    """
    GROUP = "SCORPION MODULE"
    VALIDATED_MODULE_LIST = ['MIO-HDMI-OUT1-4K-IP', "MIO-HDMI-IN1-4K-IP",
                             "MIO-AES-D4", "MIO-AES-LTC-D4", "MIO-AES-OUT4-IP",
                             "MIO-AES-IN4-IP", "MIO-AES-OUT4-IP", "MIO-AES-IP",
                             "MIO-AVR", "MIO-AVT", "MIO-CCE-AUX-IO",
                             "MIO-GE-RJ45-IP", 'MIO-DANTE', "MIO-DM4-LB4",
                             "MIO-DD4-3G", "MIO-DE4-3G", "MIO-GE-RJ45-IP",
                             "MIO-HDMI-2-4K-IP", "MIO-HDMI-IN-3G(-SA)",
                             "MIO-HDMI-IN1-4K-IP", "MIO-HDMI-OUT-3G",
                             ]
    # FULL_MODULE_LIST = [
    #     "MIO-AES-D4", "MIO-AES-LTC-D4", "MIO-AES-IN4-IP" "MIO-AES-OUT4-IP",
    #     "MIO-AES-IP", "MIO-AES-IN6-OUT6", "MIO-AVR", "MIO-AVT", "MIO-BLADE-Z21",
    #     "MIO-CCE-AUX-IO", "MIO-CCE-3G", "MIO-CCE-4K", "MIO-CCM-3G", "MIO-CCM-4K",
    #     "MIO-DANTE", "MIO-DD4-3G", "MIO-DE4-3G", "MIO-DM4-LB4", "MIO-DSP-AUD",
    #     "MIO-GE-RJ45", "MIO-GE-RJ45-IP", "MIO-HDMI-2-4K-IP", "MIO-HDMI-IN-3G(-SA)",
    #     "MIO-HDMI-IN-4K", "MIO-HDMI-IN1-4K-IP", "MIO-HDMI-OUT-3G", 'MIO-HDMI-OUT-4K'
    #     'MIO-HDMI-OUT-4K-IP', 'MIO-HDMI-OUT1-4K-IP', "MIO-IT-IP", "MIO-MADI-2-IP",
    #     "MIO-SFP", "MIO-USB-A", "MIO-USB-B", "MIO-VB-2-12G", "MIO-VTR-2-12G", "MIO-XPS"
    #     "MIO-XPS-1E1D", "MIO-CPU", "MIO-T1E1", "MIO-WANPTP"]

    def __init__(self, scorpion_frame_obj, module_name: str,
                 module_slot: int, validation_device_name=''):
        """
        The init method will initialize the scorpion object.
        It will probe the device for the modules and populate 'card_name',
        'webVerList'
        module_name: The name of the scorpion module <str>
        module_slot: The slot the module resides in <int>
        validation_device_name: Some devices use a different name in the
                                Firmware or Product.regex file. Defaults
                                to module_name if empty.

        Variables:
            self.name
            self.slot
            self.frame
            self.firmware
            self.filename
            self.validation_device_name
            self.flags
            self.webVerList


        """
        super().__init__(scorpion_frame_obj)
        # print(f"IP:{self.IP}, name:{self.name}, http:{self.http}, snmp:{self.snmp}, cfgweb:{self.cfgweb}, cfgjson:{self.cfgjson}, results:{self.results}, interfaces:{self.interfaces}, started:{self.started}")
        self.flags = {
            'uploadFinished': False, 'upgradeFinished': False,
            'pollFinished': False, 'cleandiskFinished': False,
            'upgradeError': False, 'webcfgFinished': False,
            'upgradeActive': False, 'rebooting': False,
            'supported': False
        }
        # Copy the results so we can modify them
        self.results = copy.copy(scorpion_frame_obj.results)
        self.results['mac'] = '-'
        # Upgrade firmware (file) and filepath
        self.firmware = None
        self.filename = None
        # self.current_firmware = None
        # Find out which type of model the Scorpion passed is.
        self.name = module_name
        self.slot = module_slot             # 0 based
        self.setup_validation_variable(module_name, validation_device_name)
        self.probe_module()

    def probe_module(self):
        """
            The Scorpion will probe for these extra Varids:
                Module Firmware Version
                    2003@s on Scorp 6,
                    10003@s on Scorp 4,
                    5003@s Scorp 2 & Scorpion X18 Frames.
                Module Serial Number:
                    2002@s on Scorp 6,
                    10002@s on Scorp 4,
                    5002@s Scorp 2 & Scorpion X18 Frames.
                Module Control Network IP:
                    2008@s on Scorp 6,
                    10008@s on Scorp 4,
                    5008@s Scorp 2 & Scorpion X18 Frames.

        """
        # List of the varid's last numbers which we want to poll.
        varid_extentions = ['2', '3', '8']
        base_varid = ''
        # Go through the modules that the scorpion has inside of it.
        if ("SCORPION-2" == self.frame or "SCORPION-X18" == self.frame or
                "SCORPION-SX18" == self.frame):
            # X18, S18 or Scorpion 2: Get the Firmware and Serial Number
            base_varid = '500'
            for varid_ext in varid_extentions:
                varid = f'{base_varid}{varid_ext}'
                self.requests.setdefault('httpOp', []).append('%s.%s@s' % (
                    varid, self.slot))
        elif ("SCORPION-4" == self.frame or "3606FRS" == self.frame):
            # Scorpion 4 or 3606FRS Get the Firmware and Serial Number
            base_varid = '1000'
            for varid_ext in varid_extentions:
                varid = f'{base_varid}{varid_ext}'
                self.requests.setdefault('httpOp', []).append('%s.%s@s' % (
                    varid, self.slot))
        elif ("SCORPION-6" == self.frame or "SCORPION-6F" == self.frame):
            # Scorpion 6 Get the Firmware and Serial Number
            base_varid = '200'
            for varid_ext in varid_extentions:
                varid = f'{base_varid}{varid_ext}'
                self.requests.setdefault('httpOp', []).append('%s.%s@s' % (
                    varid, self.slot))
        else:
            print(f"DEBUG: I did not find the Frame that I needed. {self.frame}")
            return None
        # for op in self.requests.pop('httpOp'):
        # self.current_firmware = self.http_thread.get_cfgjson(self.IP, self.requests.pop('httpOp')).result
        # Get the results
        probe_results = self.http_thread.get_cfgjson(self.IP, self.requests.pop('httpOp'))
        # Get the current firmware of this module/slot
        self.current_firmware = probe_results.result.get(f'{base_varid}3.{self.slot}@s', 'Not Found')
        # Get the current firmware of this module/slot
        serial = probe_results.result.get(f'{base_varid}2.{self.slot}@s',
                                          self.results['serial'])
        # If we find the serial number set it.
        if serial:
            self.results['serial'] = serial
        else:
            self.results['serial'] = '-'
        # self.results['mac'] = probe_results.result.get(f'{base_varid}2.{self.slot}@s', 'Not Found')
        # Get the IP of the device if it has any
        module_ip = probe_results.result.get(f'{base_varid}8.{self.slot}@s', '')
        if len(module_ip) > 5:
            if module_ip == self.IP:
                # If the module IP is the same as the module IP (No IP)
                return None
            self.IP = module_ip
            # Poll for the module mac if the IP is found. (103.<slot>) 112 or 106
            mac_varids = ['103', '112', '106', '357', '134']
            for varid in mac_varids:
                # NOTE: This might not work as I expect 112.3 when 112 is the varid
                varid = f'{varid}'
                probe_results = self.http_thread.get_cfgjson(self.IP, [varid])
                mac = probe_results.result.get(varid, '')
                # print(f"mac:{mac}, IP:{self.IP}, module_ip:{module_ip}")
                if len(mac) > 4:
                    self.results['mac'] = mac
                    break
        return None

    def validate_upgrade_firmware(self, filepath):
        """ This method will take apart the tar.gz file passed and will check what device is
            supported.

            required_files (inside tar.gz) = {
                'checksum.md5': Contains 'firmware.img'
                'firmware.img': Firmware to be installed
                'prod.regex': Contains the device name that this firmware
                              belongs to.
                'version': The version that we are switching to}

            1. Open the tar.gz file
            2. Check that all of the files needed are present.
                (checksum.md5, firmware.img, prod.regex and version.)
            3. Check that checksome contains a file inside called 'firmware.img'
            4. Check that the prod.regex file has 'SCORPION' as the only field inside
            5. Check that the version file has a proper version inside the file.?

            this method will set the self.upgrade_file field to contain the tar
            returns a touple (firmware_device, firmware_version)
            ex:
                supported: True if raises valueError if not supported
                firmware_device: 'SCORPION-6'
                firmware_version: 'Version 1.0 build 137'
        """
        # supported = False
        required_files = {'checksum.md5': False, 'firmware.img': False,
                          'prod.regex': False, 'version': False}
        # 1. Open the tar.gz file
        try:
            tar = tarfile.open(str(filepath), 'r:gz')
        except Exception as error:
            raise ValueError("The firmware passed is not a tar.gz file.  "
                  "Please pass in the correct firmware file for the selected "
                  "device. path: %s, error: %s " % (filepath, error))
        files_inside = tar.getmembers()
        # 2. Check that all of the files needed are present.
        for file in files_inside:
            # Pull filename and extract the file.
            filename = file.name
            try:
                extracted_file = tar.extractfile(file)
            except KeyError:
                raise ValueError('There was an issue extracting the data from '
                                 'the tar file. Invalid file given. path: '
                                 '%s' % filepath)
            # 3. Check that checksome contains a file inside called 'firmware.img'
            if filename == 'checksum.md5' and file.isfile():
                data = extracted_file.read().decode('utf8').strip()
                if 'firmware.img' in data:
                    required_files[filename] = True
                else:
                    raise ValueError("There was a problem validating the "
                                     "'checksum.md5' file. checksum.md5 "
                                     "could not find the img checksome. "
                                     "Data: %s" % (data))
            # 4. Check that the prod.regex file has 'SCORPION' as the only field inside
            if filename == 'prod.regex' and file.isfile():
                # check that the file contains the proper information
                data = extracted_file.read().decode('utf8').strip()
                firmware_device = data
                if self.validation_device_name in data or self.name in data:
                    required_files[filename] = True
                else:
                    raise ValueError("There was a problem validating the "
                                     "'prod.regex' file. prod.regex does not "
                                     f"have '{self.validation_device_name}' "
                                     f"in the file. Data: {data}")
            # 5. Check that the version file has a proper version inside the file.?
            if filename == 'version' and file.isfile():
                # check that the version contains the proper information ex:'Version 1.0 build 137'
                data = extracted_file.read().decode('utf8').strip()
                expression = "Version [0-9]*.[0-9]* build *"
                re_expression = re.compile(expression)
                firmware_version = data
                if re_expression.match(data):
                    required_files[filename] = True
                else:
                    raise ValueError("There was a problem validating "
                                     "the 'version' file. Version does not "
                                     "match expected format: "
                                     "'%s' Data: %s" % (expression, data))
            if filename == 'firmware.img' and file.isfile():
                required_files[filename] = True
        if False in list(required_files.values()):
            raise ValueError("One of the files that are required were not "
                             "found. required_files: %s" % (required_files))
        return (firmware_device, firmware_version)

    def upgrade(self, filepath):
        """
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

        Modules:
        MIO-HDMI-IN1-4K-IP

        NOTE: We need to restart snmp threads in this method.

        """
        # Slot in the upgrade process is 1 based
        slot = self.slot + 1
        self.flags.update({'uploadFinished': False, 'upgradeFinished': False,
                           'cleandiskFinished': False, 'upgradeError': False,
                           'upgradeActive': False})

        self.image_path = filepath
        self.firmware = open(filepath, 'rb')
        self.requests = {}
        # Validate if image dictionary is present when passed.
        if not filepath or not self.firmware:
            raise ValueError("No image file found!")
        # if not self.stored['version']:
        #     raise ValueError("No image version detected!")
        # Validate if upgrade file is valid
        self.restart_snmp_threads()
        self.requests['login'] = self.login()
        time.sleep(5)
        self.flags.update({'upgradeActive': True})
        filename = filepath.split("\\")[-1]
        # Check if device is using http or https
        str_https = 'http'
        if self.https:
            str_https = 'https'
        # get the size of the file and store it in the device if its suppoerted
        firmware_size = os.path.getsize(filepath)
        # progress_dialog.Update(10, "Start the upgrade...")
        command = (f'{str_https}://{self.IP}/cgi-bin/' +
                   f'upgradeprep?slots={slot}&' +
                   f'size={firmware_size}')
        # GET /cgi-bin/upgradeprep?slots=1&size=31447368 HTTP/1.1
        op = self.http_thread.get(command)
        # {"result":{"value":0}}\n
        start_msg = op.content.decode('utf-8')
        # Validate that we are working with a frame.
        # print(f"firmware_size: {firmware_size}, start_msg:{start_msg}, ")
        if not op.ok:
            raise ValueError("There was a problem Upgrading the system. "
                             "There was no reply from the infor.conf get"
                             " ok:%s, content:%s error:%s " % (
                             op.ok, op.content, op.error))
        #Send the tar.gz file
        # POST /v.1.5/php/features/feature-transfer-upload.php?filename=MIO-HDMI-IN1-4K-IP-V0100-20200326-B75.tar.gz HTTP/1.1
        # Payload == file
        # progress_dialog.Update(25, "Send the firmware to the card...")
        command = (f'{str_https}://{self.IP}/{self.webeasy_version}/php/features/' +
                  f'feature-transfer-upload.php?filename={filename}')
        print(f"Sending the upgrade file '{filename}' to the device using " +
              f"POST command {command}.")
        headers = {'Content-Type': 'multipart/form-data',}
        data = self.firmware.read()
        op = self.http_thread.post(command, data=data, headers=headers, timeout=600)
        # Validate that the reply is in this format
        try:
            content = op.content.decode('utf-8')
            print(f"DEBUG: UploadFile command: {command}, op.error:{op.error}, content:{content}")
            # Reply should be 'Completed Upload - /tmp/upgrade-files/SCORPION-6.tar.gz size:70667019--existing:1\n'
            if (op.finished and (not op.ok or op.error or 'Completed Upload' not in content)):
                self.flags['upgradeError'] = True
                raise ValueError("There was a problem Uploading the file %s. " % (filename) +
                                "ok:%s, content:%s error:%s " % (
                                op.ok, op.content, op.error))
        except Exception as error:
            print(f"ERROR: {error}")
            # progress_dialog.Update(100, f'error: {error}')
            return None
        self.flags['uploadFinished'] = True
        # GET /cgi-bin/upgradecgi?file=MIO-HDMI-IN1-4K-IP-V0100-20200326-B75.tar.gz&slot=1&time=1687883359455 HTTP/1.1
        # progress_dialog.Update(80, "Finished uploading the file. Upgrading " +
                            #    "Device..\nThis can take up to 10 minutes.")
        command = (f'{str_https}://{self.IP}/cgi-bin/upgradecgi?file=' +
                   f'{filename}&slot={slot}&time={time.time()}')
        headers = {
            "Accept": "text/event-stream",
            "Referer": f"http://{self.IP}/card.upgrade.php",
            "Accept-Encoding": "gzip, deflate"}
        op = self.http_thread.get(command, headers=headers, timeout=600)
        content = op.content.decode('utf-8')
        print(f"DEBUG: Start polling command: {command}, op.error:{op.error}, content:{content}")
        # Wait 10 seconds for the device to finish
        # progress_dialog.Update(100, "Completed Upgrade. Rebooting Card.")
        time.sleep(30)
        # Then we poll for the response from the device
        # finished = False
        # TIMEOUT = 60 * 8
        # start_time = time.time()
        # end_time = start_time + TIMEOUT
        # command = (f'{str_https}://{self.IP}/' +
        #            f'{self.webeasy_version}/php/features/' +
        #            'feature-user-management.php?' +
        #            'action=active-user')
        # while finished is False:
        #     # GET /v.1.5/php/features/feature-user-management.php?action=active-user HTTP/1.1
        #     progress_dialog.Update(45, "Wait for upgrade to finish...")
        #     op = self.http_thread.get(command)
        #     # Expected reply:  [truncated]{  "active"   : true,  "username" : "root",  "role"     : {"name":"administrator","deleteable":false,"restrictions":["oauth2-settings"]}, "session"  : { "last-activity" : 1541388169, "current-inactivity"   : 42, "remaining-ina
        #     poll_response = op.content.decode('utf-8').replace(' ', '')
        #     # poll_response: '{"active":true,"username":"root"....
        #     is_active = poll_response.split(',')[0].split(':')[1]
        #     print(f"DEBUG: poll_response:{poll_response}, is_active:{is_active}")
        #     if is_active == 'false':
        #         progress_dialog.Update(95, "Completed Upgrade. Rebooting Card.")
        #         break
        #     time.sleep(30)
        #     # If 'active' is False, upgrade is finished
        #     if not op.ok:
        #         progress_dialog.Update(100, f'error: {op.error}')
        #         raise ValueError(f"There was a problem Upgrading the {self.IP}:"
        #                          f"{self.name}. There was no reply from the "
        #                          "infor.conf get ok:%s, content:%s error:%s" % (
        #                          op.ok, op.content, op.error))
        #     if time.time() >= end_time:
        #         raise ValueError(f"There was a problem Upgrading {self.IP}:"
        #                          f"{self.name}. It took more then 10 minutes.")
        # progress_dialog.Update(100, "Completed Upgrade. Rebooting Card.")
        self.flags['upgradeActive'] = False
        self.flags['upgradeFinished'] = True
