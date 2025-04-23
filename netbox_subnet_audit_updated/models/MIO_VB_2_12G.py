import time
import os

# from models.scorpion_module import ScorpionModule
import models.scorpion_module

class ScorpionModule(models.scorpion_module.ScorpionModule):
    """
        This class is created to store modules that use the have upgrade
        files that end with the '.app' filename.
        This class has methods to:
            'upgrade' Method, will upgrade the scorpion Frames.
            'reboot' method will reboot the card
            'login' method will login to the device's webeasy page.
            'validate_upgrade_firmware' method will validate that the firmware
                file passed has all of the required files needed to upgrade
                properly.

        Variables:
            self.name
            self.slot
            self.frame
            self.firmware
            self.filename
            self.validation_device_name
            self.flags
            self.webVerList

        NOTE: This device is different compared to the scorpion_module class,
              This class is used to validate .app files.

              This Module is used for:
                'MIO-GE-RJ45', "MIO-VB-2-12G"
    """
    GROUP = "SCORPION MODULE"
    VALIDATED_MODULE_LIST = ['MIO-GE-RJ45', "MIO-VB-2-12G", "MIO-HDMI-OUT-4K"]

    def __init__(self, scorpion_frame_obj, module_name: str,
                 module_slot: int):
        """
        The init method will initialize the scorpion object.
        It will probe the device for the modules and populate 'card_name',
        'webVerList'
        module_name: The name of the scorpion module <str>
        module_slot: The slot the module resides in <int>

        """
        super().__init__(scorpion_frame_obj, module_name, module_slot)
        # print(f"IP:{self.IP}, name:{self.name}, http:{self.http}, snmp:{self.snmp}, cfgweb:{self.cfgweb}, cfgjson:{self.cfgjson}, results:{self.results}, interfaces:{self.interfaces}, started:{self.started}")
        self.flags = {
            'uploadFinished': False, 'upgradeFinished': False,
            'pollFinished': False, 'cleandiskFinished': False,
            'upgradeError': False, 'webcfgFinished': False,
            'upgradeActive': False, 'rebooting': False,
        }
        # Upgrade firmware (file) and filepath
        self.firmware = None
        self.filename = None
        # print(f"DEBUG: MIO_VB_2_12G: name:{self.name}, slot:{self.slot}, validation_device_name:{self.validation_device_name}")
        # self.probe()

    def validate_upgrade_firmware(self, filepath):
        """ This method will take apart the tar.gz file passed and will check what device is
            supported.
            1. Open the .app file
            2. Validate that the device name is in the binary file

            this method will set the self.upgrade_file field to contain the tar
            returns a touple (firmware_device, firmware_version)
            ex:
                firmware_device: 'MIO_VB_2_12G'
                firmware_version: 'Name of Device'

            NOTE: Supports .app files. NOT .TAR.GZ
        """
        # supported = False
        # required_files = {}
        firmware_version = filepath.split('\\')[-1]
        firmware_device = self.name
        print(f"DEBUG: MIO_VB Firmware version; {firmware_version}, {firmware_device}")
        # Open up the file and check if the name of the device is in the file.
        f = open(filepath, 'rb')
        contents = f.read()
        f.close()
        if firmware_device in str(contents):
            return (firmware_device, firmware_version)
        else:
            raise ValueError("The device name was not found in the .app file"
                             "when converted to binary. file: "
                             f"{firmware_version}")

    def upgrade(self, filepath):
        """
        Initiates an upgrade of the device with the given 'image_dict'
        and its originating 'filepath' (including path).
        Can possibly spawn a new thread, or perform upgrade
        during poll_upgrade() calls.
        Does not block. Returns right away.
        If the image is not suitable, raise an exception
        in the next poll_upgrade() call.

        Modules:
        MIO-HDMI-IN1-4K-IP

        NOTE: Same thing as ScorpionModule, but decreased wait time for the
              last http message

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
        self.flags.update({'upgradeActive': True})
        filename = filepath.split("\\")[-1]
        # Check if device is using http or https
        str_https = 'http'
        if self.https:
            str_https = 'https'
        # get the size of the file and store it in the device if its suppoerted
        firmware_size = os.path.getsize(filepath)
        # progress_dialog.Update(10, "Start the upgrade...")
        # GET /cgi-bin/upgradeprep?slots=1&size=31447368 HTTP/1.1
        op = self.http_thread.get((f'{str_https}://{self.IP}/cgi-bin/' +
                                   f'upgradeprep?slots={slot}&' +
                                   f'size={firmware_size}'))
        # {"result":{"value":0}}\n
        start_msg = op.content.decode('utf-8')
        # Validate that we are working with a frame.
        print(f"firmware_size: {firmware_size}, start_msg:{start_msg}, ")
        if not op.ok:
            comment = ("There was a problem Upgrading the system. "
                       "There was no reply from the infor.conf get"
                       f"{self.IP}:{self.name}."
                       f"ok:{op.ok}, content:{op.content} error:{op.error}")
            self.flags['upgradeError'] = comment
            self.flags['upgradeFinished'] = True
            raise ValueError(comment)

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
        op = self.http_thread.post(command, data=data, headers=headers, timeout=20)
        # Validate that the reply is in this format
        try:
            content = op.content.decode('utf-8')
            print(f"DEBUG: UploadFile command: {command}, op.error:{op.error}, content:{content}")
            # Reply should be 'Completed Upload - /tmp/upgrade-files/SCORPION-6.tar.gz size:70667019--existing:1\n'
            if (op.finished and (not op.ok or op.error or 'Completed Upload' not in content)):
                comment = (f"There was a problem Upgrading the file {filename}."
                           f"{self.IP}:{self.name}. There was no reply from the "
                           "infor.conf get."
                           f"ok:{op.ok}, content:{op.content} error:{op.error}")
                self.flags['upgradeError'] = comment
                self.flags['upgradeFinished'] = True
                raise ValueError(comment)
        except Exception as error:
            print(f"ERROR: {error}")
            # progress_dialog.Update(100, f'error: {error}')
            return None
        self.flags['uploadFinished'] = True
        # GET /cgi-bin/upgradecgi?file=MIO-HDMI-IN1-4K-IP-V0100-20200326-B75.tar.gz&slot=1&time=1687883359455 HTTP/1.1
        # progress_dialog.Update(40, "Finished uploading the file...")
        # command = (f'{str_https}://{self.IP}/v.fc/cgi-bin/upgradecgi?file=' +
        #             f'{filename}&slot={self.slot}&time={time.time()}')
        command = (f'{str_https}://{self.IP}/cgi-bin/upgradecgi?file=' +
                   f'{filename}&slot={slot}&time={time.time()}')
        op = self.http_thread.get(command)
        content = op.content.decode('utf-8')
        print(f"DEBUG: Start polling command: {command}, op.error:{op.error}, content:{content}")

        # Then we poll for the response from the device
        finished = False
        TIMEOUT = 60 * 2
        start_time = time.time()
        end_time = start_time + TIMEOUT
        command = (f'{str_https}://{self.IP}/' +
                   f'{self.webeasy_version}/php/features/' +
                   'feature-user-management.php?' +
                   'action=active-user')
        while finished is not True:
            # GET /v.1.5/php/features/feature-user-management.php?action=active-user HTTP/1.1
            # progress_dialog.Update(45, "Wait for upgrade to finish...")
            op = self.http_thread.get(command)
            # Expected reply:  [truncated]{  "active"   : true,  "username" : "root",  "role"     : {"name":"administrator","deleteable":false,"restrictions":["oauth2-settings"]}, "session"  : { "last-activity" : 1541388169, "current-inactivity"   : 42, "remaining-ina
            poll_response = op.content.decode('utf-8')
            print(f"DEBUG: poll_response:{poll_response}")
            # If 'active' is False, upgrade is finished
            if not op.ok:
                # progress_dialog.Update(100, f'error: {op.error}')
                comment = (f"There was a problem Upgrading the {self.IP}:"
                           f"{self.name}. There was no reply from the "
                           "infor.conf get."
                           f"ok:{op.ok}, content:{op.content} error:{op.error}")
                self.flags['upgradeError'] = comment
                self.flags['upgradeFinished'] = True
                raise ValueError(comment)
            if time.time() >= end_time:
                comment = (f"There was a problem Upgrading {self.IP}:"
                            f"{self.name}. It took more then 10 minutes.")
                self.flags['upgradeError'] = comment
                self.flags['upgradeFinished'] = True
                raise ValueError(comment)
            if "active" in poll_response:
                # progress_dialog.Update(95, "Completed Upgrade. Rebooting Card.")
                finished = True
            time.sleep(10)
        # progress_dialog.Update(100, "Completed Upgrade. Rebooting Card.")
        self.flags['upgradeActive'] = False
        self.flags['upgradeFinished'] = True

