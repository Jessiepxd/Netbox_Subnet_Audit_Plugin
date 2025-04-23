import models.Model as Model
# import models.scorpion_module as scorpion_module
import time
import tarfile
import re
import copy
# import upgrade_lib

class Scorpion(Model.Device):
    """
        This class is created to store Scorpion Frame objects.
        This class has methods to:
            'upgrade' Method, will upgrade the scorpion Frames.
            'reboot' method will reboot the card
            'login' method will login to the device's webeasy page.
            'validate_upgrade_firmware' method will validate that the firmware
                file passed has all of the required files needed to upgrade
                properly.

        Variables:
            self.IP = String IP address of device.
            self.name = Discovered name of the device.
            self.modules = The submodules of this frame
            self.firmware = Used to store the open file as bytes.
            self.filename = The full path to the firmware as a string
            self.slot = The slot that the module is located in
            self.flags = Flags that are used to determine different settings
            self.requests = A dictionary holding all of our requests

        Scorpion Modules Overwrite:
            self.name
            self.firmware
            self.filename
            self.flags
            self.requests
            self.current_firmware
            self.results



    """
    GROUP = "SCORPION"
    # What type of frame is in the device
    FRAME_LIST = ["3606FRS", "SCORPION-2", "SCORPION-4", "SCORPION-6",
                  "SCORPION-6F", "SCORPION-X18", "SCORPION-SX18"]
    MODULE_LIST = [
        "MIO-AES-D4", "MIO-AES-LTC-D4", "MIO-AES-IN4-IP" "MIO-AES-OUT4-IP",
        "MIO-AES-IP", "MIO-AES-IN6-OUT6", "MIO-AVR", "MIO-AVT", "MIO-BLADE-Z21",
        "MIO-CCE-AUX-IO", "MIO-CCE-3G", "MIO-CCE-4K", "MIO-CCM-3G", "MIO-CCM-4K",
        "MIO-DANTE", "MIO-DD4-3G", "MIO-DE4-3G", "MIO-DM4-LB4", "MIO-DM-TRK-SA",
        "MIO-GE-RJ45", "MIO-GE-RJ45-IP", "MIO-HDMI-2-4K-IP", "MIO-HDMI-IN-3G",
        "MIO-DSP-AUD", "MIO-HDMI-IN-4K", "MIO-HDMI-IN1-4K-IP", "MIO-HDMI-OUT-3G",
        "MIO-HDMI-OUT-4K", "MIO-HDMI-OUT-4K-IP", "MIO-HDMI-OUT1-4K-IP",
        "MIO-IT-IP", "MIO-MADI-2-IP", "MIO-SFP", "MIO-USB-A", "MIO-USB-B",
        "MIO-VB-2-12G", "MIO-VTR-2-12G", "MIO-XPS", "MIO-XPS-1E1D", "MIO-CPU",
        "MIO-T1E1", "MIO-WANPTP"]

    UNSUPPORTED_LIST = ["MIO-CCE-3G", "MIO-CCE-4K", "MIO-CCM-3G", "MIO-CCM-4K",
                        "MIO-DM4-LB4", "MIO-DSP-AUD", "MIO-HDMI-OUT-4K-IP",
                        "MIO-DM-TRK-SA", "MIO-CPU", "MIO-T1E1", "MIO-WANPTP",
                        "MIO-XPS-1E1D"]

    SUPPORTED_MODULE_LIST = [
        # Base ScorpionModule (.tar.gz file validation)
        "MIO-AES-D4", "MIO-AES-LTC-D4", "MIO-AES-IN4-IP",
        "MIO-AES-OUT4-IP", "MIO-AES-IP", "MIO-AVR", "MIO-AVT",
        "MIO-DANTE", "MIO-DM4-LB4", "MIO-DM-TRK-SA",
        "MIO-GE-RJ45-IP", "MIO-HDMI-2-4K-IP", "MIO-HDMI-IN-3G",
        "MIO-HDMI-IN1-4K-IP", "MIO-HDMI-OUT-3G",
        "MIO-HDMI-OUT1-4K-IP", "MIO-IT-IP",
        "MIO-USB-A", "MIO-USB-B",
        # MIO_AES_IN6_OUT6 (.tar.gz. extra md5 checksum file)
        "MIO-AES-IN6-OUT6", "MIO-SRG",
        # MIO_CCE_AUX_IO (.CIU (zip) file validation)
        "MIO-CCE-AUX-IO", "MIO-DD4-3G", "MIO-DE4-3G",
        # MIO_VB_2_12G (.app validation)
        "MIO-XPS", "MIO-VTR-2-12G", "MIO-VB-2-12G",
        "MIO-SFP", "MIO-HDMI-OUT-4K", "MIO-HDMI-IN-4K",
        "MIO-GE-RJ45",
        # MIO-HDMI-2-4K-IP (.tar.gz extra img files)
        "MIO-HDMI-2-4K-IP",
        # Base EVBLADES (.CIU (zip) file validation)
        "MIO-APP-XS-2E2D", "MIO-APP-XS-1E3D",
        "MIO-APP-XS-3E1D", "MIO-APP-UDX-3G",
        "MIO-APP-UDX-4K", "MIO-APP-CCE",
        "MIO-APP-DLY", "MIO-APP-DLY2",
        "MIO-APP-IPG-ST2110-AES", "MIO-APP-IPG-ST2022",
        "MIO-APP-IPG-ST2022-A", "MIO-APP-IPG-ST2022-B"
        "MIO-APP-IPG-ST2110", "MIO-APP-IPG-ST2110-A",
        "MIO-APP-IPG-ST2110-B",
        # EVBLADE J2K (.tar.gz file validation)
        "MIO-APP-J2K-1E1D", "MIO-APP-J2K-2E", "MIO-APP-J2K-2D"
        ]

    # def __repr__(self):
    #     return (f"IP: {self.IP}, Device Name: {self.name}, modules: {self.modules}, firmware: {self.firmware}, filename: {self.filename}, results:{self.results}, webeasy: {self.webeasy_version}")
    def temp(self):
        return (f"IP: {self.IP}, Device Name: {self.name}, modules: {self.modules}, firmware: {self.firmware}, filename: {self.filename}, results:{self.results}, webeasy: {self.webeasy_version}")

    def setup_validation_variable(self, module_name, validation_device_name):
        """
            This method will configure self.validation_device_name to a value
        """
        # Different name if the device validation calls for one
        if validation_device_name:
            self.validation_device_name = validation_device_name
        else:
            self.validation_device_name = module_name

    # def restart_snmp_threads(self):
    #     """
    #         This method is used to restart the SNMP threads.
    #         The SNMP threads usually die when passed through the objects so
    #         before the upgrade we will check and instantiate them
    #     """
    #     if not self.snmp_thread.is_alive() or not self.http_thread.is_alive():
    #         self.snmp_thread = Model.asnmp.start()
    #         self.http_thread = Model.ahttp.start()

    def __init__(self, device_info_object):
        """
        The init method will initialize the scorpion object.
        It will probe the device for the modules and populate 'card_name',
        'webVerList'

        device_info_object: A DeviceInfo object. Found in devicelab.py
        Inherited from DeviceLab:
            self.name = Discovered name of the device.
            self.modules = The submodules of this frame
            self.firmware = Used to store the open file as bytes.
            self.filename = The full path to the firmware as a string
            self.slot = The slot that the module is located in
            self.flags = Flags that are used to determine different settings
            self.requests = A dictionary holding all of our requests
            self.current_firmware = The current firmware for the device



            We probe a device for SNMP/LLDP, HTTP/WebEASY, and NetBIOS.
            The SNMP results go into self.snmp:
            self.snmp = {OID: value} and will be empty if the device did not
                        responds to SNMP packets.
                { sysDescr, sysName, sysObjectID, sysLocation }
            All HTTP results go into self.http:
            self.http = {
                'content': bytes,     # Raw bytes of the '/' path, if not WebEASY.
                'headers': dict       # Response headers as {name: value}.
                'status_code': int    # The HTTP response code for the '/' path.
                'version': str,       # WebEASY version, if found, as "v.#.#".
                'https': bool,        # If the HTTP server was HTTP or HTTPS.
                'cfg_json': dict,     # Reply from cfgJSON request (if any).
                'cfg_web': dict,      # Reply from cfgWeb request (if any).
                }

            From the above, we populate self.results with all processed
            information from all replies. It can contain any of the following:
            self.results = {
                'enterprise': int,      # From sysObjectID or SNMPv3 engineID.
                'vendor': str,          # From 'enterprise' number, if found.
                'netbios': str,         # Possibly from NetBIOS query.
                'card_name': str,       # From cardName OID or WebEASY 1@s.
                'serial': str,          # From boardSerialNumber OID or WebEasy 8@s.
                'mac': str,             # The best-guess MAC address for this device.
                'alias': str,           # Card alias name given by user.
                'major': int,           # FW version softwareRevisionMajor OID or WebEasy 3@i.
                'minor': int,           # FW version softwareRevisionMinor OID or WebEASY 4@i.
                'build': int,           # FW version softwarePointReleaseNumber or WebEASY 6@s.
                'board_name': str,      # boardName OID or WebEASY 9@s.
                'board_rev': str,       # boardRevision OID or Webeasy 10@s
                'board_build': int,     # boardBuild OID or Webeasy 11@i
                'http_name': str,       # Best-guess name of HTTP server or `None`.
                }

        """
        super().__init__(device_info_object)
        # print(f"IP:{self.IP}, name:{self.name}, http:{self.http}, snmp:{self.snmp}, cfgweb:{self.cfgweb}, cfgjson:{self.cfgjson}, results:{self.results}, interfaces:{self.interfaces}, started:{self.started}")
        self.flags = {
            'uploadFinished': False, 'upgradeFinished': False,
            'pollFinished': False, 'cleandiskFinished': False,
            'upgradeError': False, 'webcfgFinished': False,
            'upgradeActive': False, 'rebooting': False,
        }
        self.modules = None
        # Upgrade firmware (file) and filepath
        self.firmware = None
        self.filename = None
        # Used for validation if the official device name is different on the firmware.
        self.validation_device_name = None
        self.results = copy.copy(device_info_object.results)
        self.slot = None
        # self.GROUP = "SCORPION"
        # Scorpion 2 requires a login
        self.login()
        # print(f"DEBUG: current scorpion_firmware {self.current_firmware}")
        # Find out which type of model the Scorpion passed is.
        card_name = self.results.get('card_name')
        if card_name in self.FRAME_LIST:
            # Set the name of the card, as well as the frame.
            self.name = card_name
            self.frame = card_name
        # v
        # Pull the module names 2001@s on scorp 6 1001@s on 4, 5001@s on Scorpion 2 & Scorpion X18
        self.probe()

    def pull_firmware(self, varid='53@s'):
        """ A method to pull the firmware of the device using its varid.
        Usually used to make sure that the firmware is the same before
        and after upgrades

        Parameter:
            varid_int: <String> The complete Varid. ex: 53@s
        """
        varid_list = ['%s' % (varid)]
        # returns {'53@s': 'Version 1.0 build 137'}
        op = self.http_thread.get_cfgjson(self.IP, varid_list).result
        # Get the parameter
        return op.get(varid)
        # self.current_firmware = op.get(varid)

    def probe(self):
        """
            The Scorpion will probe for these extra Varids:
                2001@s on Scorp 6, 1001@s on Scorp 4, 5001@s Scorp 2 &
                Scorpion X18 Frames.

        """
        # Go through the modules that the scorpion has inside of it.
        present_modules = []
        if self.name in ("SCORPION-2", "SCORPION-X18", "SCORPION-SX18"):
            # X18, S18 or Scorpion 2
            varid = '5001'
            if '18' in self.name:
                for module in range(0, 18):
                    self.requests.setdefault('httpOp', []).append('%s.%s@s' % (varid, module))
            else:
                for module in range(0, 2):
                    self.requests.setdefault('httpOp', []).append('%s.%s@s' % (varid, module))
        elif self.name in ("SCORPION-4", "3606FRS"):
            # Scorpion 4 or 3606FRS
            varid = '10001'
            for module in range(0, 4):
                self.requests.setdefault('httpOp', []).append('%s.%s@s' % (varid, module))
        elif self.name in ("SCORPION-6", "SCORPION-6F"):
            # Scorpion 6
            varid = '2001'
            for module in range(0, 6):
                self.requests.setdefault('httpOp', []).append('%s.%s@s' % (varid, module))
        else:
            print(f"DEBUG: I did not find the Frame that I needed. {self.name}")
            varid = None
            return None
        # for op in self.requests.pop('httpOp'):
        op_result = self.http_thread.get_cfgjson(self.IP, self.requests.pop('httpOp')).result
        present_modules = list(op_result.values())
        self.modules = present_modules

    def reboot(self, event=None):
        """
        """
        if self.name == 'SCORPION-SX18':
            self.requests['reboot'] = self.http_thread.set_cfgweb(self.IP, {'151@i': 1})
        else:
            self.requests['reboot'] = self.http_thread.set_cfgweb(self.IP, {'50@i': 1})

    # def login(self):
    #     data = {'user': 'root', 'password': 'evertz', 'SubmitPassword': 'Login'}
    #     return self.http_thread.post(
    #         'http://' + self.IP + '/login.php', data=data, block=False)

    def validate_upgrade_firmware(self, filepath):
        """ This method will take apart the tar.gz file passed and will check what device is
            supported.
            1. Open the tar.gz file
            2. Check that all of the files needed are present.
                (checksum.md5, firmware.img, prod.regex and version.)
            3. Check that checksum contains a file inside called 'firmware.img'
            4. Check that the prod.regex file has 'SCORPION' as the only field inside
            5. Check that the version file has a proper version inside the file.?

            this method will set the self.upgrade_file field to contain the tar
            returns a touple (firmware_device, firmware_version)
            ex:
                supported: True if supported, raises valueError if not supported
                firmware_device: 'SCORPION-6'
                firmware_version: 'Version 1.0 build 137'
        """
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
                # Checksum should only have 'firmware.img' inside
                data = extracted_file.read().decode('utf8').strip()
                if 'firmware.img' in data:
                    required_files[filename] = True
                else:
                    raise ValueError("There was a problem validating the "
                                     "'checksum.md5' file. checksum.md5 "
                                     "could not find the img checksome. "
                                     f"Data: {data}")
            elif filename == 'firmware.img' and file.isfile():
                # Look through the file to see if this frame is supported
                data = extracted_file.read()
                # Check for device name inside of the frame
                if bytes(self.name, 'utf-8') in data:
                    required_files[filename] = True
                elif (bytes('SCORPION-S18', 'utf-8') in data and
                        self.name == 'SCORPION-SX18'):
                    # Scorpion S18's do not match the 'card name' varid
                    required_files[filename] = True
                else:
                    print("WARNING: Frame name is not found in firmware."
                          f"filename: {filename}")
            # 4. Check that the prod.regex file has 'SCORPION' as the only field inside
            elif filename == 'prod.regex' and file.isfile():
                # check that the file contains the device name.
                data = extracted_file.read().decode('utf8').strip()
                firmware_device = data
                if self.name == "SCORPION-SX18" and data == "SCORPION-IPX":
                    required_files[filename] = True
                if self.name in data:
                    # Scorpion-6 firmware usually has
                    required_files[filename] = True
                elif 'SCORPION' == data:
                    # multiple scorpion frames are possible to upgrade to.
                    required_files[filename] = True
                else:
                    raise ValueError("There was a problem validating the "
                                     "'prod.regex' file. prod.regex does not "
                                     f"have '{self.name}' in the file. "
                                     f"Data: {data}")
            # 5. Check that the version file has a proper version inside the file.?
            elif filename == 'version' and file.isfile():
                # check that the version contains the proper information ex:'Version 1.0 build 137'
                data = extracted_file.read().decode('utf8').strip()
                expression = "Version [0-9].[0-9] build *"
                re_expression = re.compile(expression)
                firmware_version = data
                if re_expression.match(data):
                    required_files[filename] = True
                else:
                    raise ValueError("There was a problem validating "
                                     "the 'version' file. Version does not "
                                     "match expected format: "
                                     "'%s' Data: %s" % (expression, data))
            else:
                print("WARNING: There was an extra file found which we did "
                      f"not expect! file: {filename} ")
        if False in list(required_files.values()):
            raise ValueError("One of the files that are required were not "
                             "found. required_files: %s" % (required_files))
        return (firmware_device, firmware_version)

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
        self.flags.update({'uploadFinished': False, 'upgradeFinished': False,
                           'cleandiskFinished': False, 'upgradeError': False,
                           'upgradeActive': False})

        self.image_path = filepath  # IS THIS USED?
        self.firmware = open(filepath, 'rb').read()
        filename = filepath.split('\\')[-1]
        self.requests = {}
        self.restart_snmp_threads()
        # Pull Firmware for comparison before & after upgrade.
        firmware_before_upgrade = self.pull_firmware('53@s')
        # Validate if image dictionary is present when passed.
        if not filepath or not self.firmware:
            raise ValueError("No image file found!")
        # if not self.stored['version']:
        #     raise ValueError("No image version detected!")
        # Validate if upgrade file is valid
        self.requests['login'] = self.login()
        self.flags.update({'upgradeActive': True})
        # Check if device is using http or https
        str_https = 'http'
        if self.https:
            str_https = 'https'
        # Get the size of the file and store it in the device if its suppoerted
        firmware_size = len(self.firmware)
        # progress_dialog.Update(10, "Validate the infor.conf file...")
        # Get the infor.conf file : GET /infor.conf HTTP/1.1
        # headers = {"If-Modified-Since": "Wed, 15 Mar 2023 14:14:26 GMT","If-None-Match": r'"524192857"'}
        op = self.http_thread.get('%s://%s/infor.conf' % (str_https, self.IP,))
        infor = op.content.decode('utf-8')
        # Validate that we are working with a frame.
        print(f"firmware_size: {firmware_size}, infor:{infor}, ")
        if not op.ok or '3606FC' not in infor:
            comment = (f"There was a problem Upgrading the system"
                       "There was no reply from the infor.conf get."
                       f"ok:{op.ok}, content:{op.content} error:{op.error}")
            self.flags['upgradeError'] = comment
            self.flags['upgradeFinished'] = True
            raise ValueError(comment)
        # progress_dialog.Update(20, "Create some space for the upgrade...")
        # Run the cleandisk Get
        # /v.fc/php/features/feature-upgrade-action.php?action=cleandisk&size=70667019 HTTP/1.1
        # How do we determine the size of the cleandisk?
        try:
            # command = '%s://%s/v.fc/php/features/feature-upgrade-action.php?action=cleandisk&size=%s' % (
            #     str_https, self.IP, firmware_size)
            # print("Cleaning the device disk. Creating temporary directory using the command %s" % (
            #     command))
            # op = self.http_thread.get(command)
            op = upgrade_lib.get_cleandisk(self.http_thread, str_https, self.IP,
                                           firmware_size, webeasy_version='v.fc')
            # Check if it passed.
            content = op.content.decode('utf-8')
            # print(f"DEBUG: CleanDisk command: {command}, op.error:{op.error}, content:{content}")
            if (not op.ok or op.error or 'cleanup' not in content or
                '/tmp/upgrade-files/' not in content):
                comment = (f"There was a problem Upgrading the system. The "
                           "reply for cleaning The disk was not what "
                           "we expected. "
                           f"ok:{op.ok}, content:{op.content} error:{op.error}")
                self.flags['upgradeError'] = comment
                self.flags['upgradeFinished'] = True
                raise ValueError(comment)
        except Exception as error:
            print(f"ERROR: {error}")
            # progress_dialog.Update(100, f'error: {error}')
            return None
        self.flags['cleandiskFinished'] = True

        #Send the tar.gz file
        # POST /v.1.5/php/features/feature-transfer-upload.php?filename=SCORPION-6.tar.gz HTTP/1.1\r\n
        # Payload == file
        # progress_dialog.Update(25, "Send the firmware to the card...")
        # command = '%s://%s/%s/php/features/feature-transfer-upload.php?filename=%s' % (
        #                                             str_https, self.IP,
        #                                             self.webeasy_version,
        #                                             filename)
        # print(f"Sending the upgrade file '{filepath}' to the device " +
        #       f"using POST command {command}")
        # headers = {"Content-Type": "multipart/form-data"}
        data = self.firmware
        # files = {filename: data}
        # op = self.http_thread.post(command, data=data, timeout=120)
        op = upgrade_lib.post_upload_file(self.http_thread,
                                          str_https, self.IP,
                                          filename,
                                          self.webeasy_version,
                                          data)

        # op = self.http_thread.post(command, files=files, timeout=120)
        # op = self.http_thread.post(command, files=files, timeout=120, headers=headers)
        # Validate that the upload completed properly
        if op.content:
            content = op.content.decode('utf-8')
        else:
            content = ''
        # print(f"DEBUG: UploadFile command: {command}, op.error:{op.error}, content:{content}")
        # Reply should be 'Completed Upload - /tmp/upgrade-files/SCORPION-6.tar.gz size:70667019--existing:1\n'
        if (op.finished and (not op.ok or op.error or 'Completed Upload' not in content)):
            comment = (f"There was a problem Uploading the firmware file."
                        f"ok:{op.ok}, content:{op.content} error:{op.error}")
            self.flags['upgradeError'] = comment
            self.flags['upgradeFinished'] = True
            raise ValueError(comment)

        # GET /v.fc/php/features/feature-upgrade-action.php?action=loghash&filename=SCORPION-6.tar.gz&date=1685036097591 HTTP/1.1
        # print("Converting the file %s to Hash format using command %s" % (filename, command))
        # progress_dialog.Update(60, "Converting to Hash format...")
        # command = (f'{str_https}://{self.IP}/v.fc/php/features/' +
        #            'feature-upgrade-action.php?action=loghash&' +
        #            f"filename={filename}&date={time.strftime('%Y%m%M%S')}")
        # op = self.http_thread.get(command)
        op = upgrade_lib.get_loghash(self.http_thread, str_https, self.IP,
                                     filename, "v.fc")
        content = op.content.decode('utf-8')
        # progress_dialog.Update(90, "Finished file upload.")
        # print(f"DEBUG: Hash1 command: {command}, op.error:{op.error}, content:{content}")

        # Execute the upgrade file
        # GET /v.fc/php/features/feature-upgrade-action.php?action=execute&filename=SCORPION-6.tar.gz&date=1685036097624 HTTP/1.1
        # progress_dialog.Update(70, "Finished Uploading file. Executing the upgrade file..")
        # command = (f'{str_https}://{self.IP}/v.fc/php/features/' +
        #            'feature-upgrade-action.php?action=execute&' +
        #            f'filename={filename}&date={time.strftime("%Y%m%M%S")}')
        # print("Execute the file %s, using command %s" % (filename, command))
        # op = self.http_thread.get(command)
        op = upgrade_lib.get_execute_file(self.http_thread, str_https,
                                          self.IP, filename,
                                          "v.fc")

        # content = op.content.decode('utf-8')
        # print(f"DEBUG: ExecuteUpgrade command: {command}, op.error:{op.error}, content:{content}")
        self.flags['upgradeActive'] = True

        # another loghash
        # GET /v.fc/php/features/feature-upgrade-action.php?action=loghash&filename=SCORPION-6.tar.gz&date=1685036118193 HTTP/1.1
        # command = (f'{str_https}://{self.IP}/v.fc/php/features/' +
        #            'feature-upgrade-action.php?action=loghash&' +
        #            f'filename={filename}&date={time.strftime("%Y%m%M%S")}')
        # # progress_dialog.Update(80, "Converting to Hash format...")
        # print("Converting the file %s to Hash format using command %s" % (filename, command))
        # op = self.http_thread.get(command)
        op = upgrade_lib.get_loghash(self.http_thread, str_https, self.IP,
                                     filename, "v.fc")
        content = op.content.decode('utf-8')
        # print(f"DEBUG: Hash2 command: {command}, op.error:{op.error}, content:{content}")

        # Check if the execution is finished?
        # # GET /v.fc/php/features/feature-upgrade-action.php?action=execute&filename=done&date=1685036118255 HTTP/1.1
        # command = (f'{str_https}://{self.IP}/v.fc/php/features/' +
        #            'feature-upgrade-action.php?action=execute&' +
        #            'filename=done&date=%s' % (time.strftime('%Y%m%M%S')))
        # # progress_dialog.Update(90, "Validate Firmware has completed upgrading...")
        # print("Check if the execution is finished using command %s" % (command))
        # op = self.http_thread.get(command)
        op = upgrade_lib.get_execute_file(self.http_thread, str_https,
                                          self.IP, "done",
                                          "v.fc")
        # print(f"Check if the execution is finished using command: {command}, "
            #   f"op.error:{op.error}, content:{content}")
        # Device will already do this
        # try:
        #     content = op.content.decode('utf-8')
        #     print(f"DEBUG: ValidateUpgade command: {command}, op.error:{op.error}, content:{content}")
        #     # Reply should be 'Command: upgradeimg "/tmp/upgrade-files/done"\n'
        #     if (op.finished and (not op.ok or op.error)):
        #         self.flags['upgradeFinished'] = True
        #         comment = (f"There was a problem execute upgrade"
        #                    f"ok:{op.ok}, content:{op.content} error:{op.error}")
        #         self.flags['upgradeError'] = comment
        #         raise ValueError(comment)
        # except Exception as error:
        #     print(f"Warning: Device failed to execute upgrade.{error}")
        #     self.flags['upgradeFinished'] = True
        #     # progress_dialog.Update(100, f'error: {error}')
        #     return None
        print("DEBUG: Completed Upgrade. Rebooting Card.")
        # progress_dialog.Update(100, "Completed Upgrade. Rebooting Card.")
        # Reboot is taken care of after execute url.
        # self.reboot()
        self.flags['upgradeActive'] = False
        self.flags['upgradeFinished'] = True
        # Pull Firmware for comparison before & after upgrade.
        print("Waiting for device to restart")
        time.sleep(350)
        firmware_after_upgrade = self.pull_firmware('53@s')
        if firmware_before_upgrade == firmware_after_upgrade:
            comment = ("Warning: The firmware before the upgrade was not the "
                       "same as the firmware after the upgrade. "
                       f"Firmware before upgrade:{firmware_before_upgrade}\n"
                       f"Firmware after upgrade:{firmware_after_upgrade}")
            print(comment)
            self.flags['upgradeError'] = comment