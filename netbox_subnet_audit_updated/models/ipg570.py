import models.Model as Model
import json
import re
from zipfile import ZipFile
import time
# from upgrade_lib import *


class IPG570(Model.Device):
    SLOT_WIDTH = 2
    GROUP = "570IPG"
    UNZIP = True
    A9List = ["570IPG-3G18-SFPP12",
              "570IPG-3G18-SFPP12-XLINK",
              "570IPG-3G18I-SFPP12",
              "570IPG-3G18I-SFPP12-XLINK",
              "570IPG-3G18O-SFPP12",
              "570IPG-3G6-SFPP6",
              "570IPG-3G9-SFPP8",
              "570IPG-3G9-SFPP8-XLINK",
              "570IPG-FK-4X2",
              "570IPG-FK-AUD-TDM"]

    X19List = ["570IPG-X19",
               "570IPG-X19-10G",
               "570IPG-X19-25G",
               "570IPG-HW-X19",
               "570IPG-NAT-6-10GE",
               "570IPG-XLINK16-DIN4",
               "570ACO-X19-10G"]

    DEVLIST = ["570IPG-X19",
               "570IPG-X19-10G",
               "570IPG-X19-25G",
               "570IPG-HW-X19",
               "570IPG-NAT-6-10GE",
               "570IPG-XLINK16-DIN4",
               "570IPG-3G18-SFPP12",
               "570IPG-3G18-SFPP12-XLINK",
               "570IPG-3G18I-SFPP12",
               "570IPG-3G18I-SFPP12-XLINK",
               "570IPG-3G18O-SFPP12",
               "570IPG-3G6-SFPP6",
               "570IPG-3G9-SFPP8",
               "570IPG-3G9-SFPP8-XLINK",
               "570IPG-FK-4X2",
               "570IPG-FK-AUD-TDM",
               "570ACO-X19-10G"]

    IOCONFIGS = {
        "auto": {'A9': (), 'X19': ()},
        "18x18": {'A9': ('A', 'D',), 'X19': ('A', 'C', 'F', 'I',)}, # apparently
        "8x8":   {'A9': (), 'X19': ('B',)}, #    A doesn't belong to 18x18 on A9
        "18x9":  {'A9': ('B', 'C', 'E',), 'X19': ()},
        "3x18":  {'A9': ('B', 'C', 'E', 'H', 'I', 'J', 'O',), 'X19': ()},
        "6x12":  {'A9': ('B', 'C', 'E',), 'X19': ()},
        "13x15": {'A9': ('F',), 'X19': ()},
        "0x18":  {'A9': ('G',), 'X19': ('E', 'H',)},
        "1x18":  {'A9': ('G',), 'X19': ()},
        "18x12": {'A9': ('H', 'I', 'J', 'O',), 'X19': ()},
        "9x9":   {'A9': ('K',), 'X19': ('D', 'G',)},
        "4x5":   {'A9': ('L',), 'X19': ()},
        "5x4":   {'A9': ('L',), 'X19': ()},
        "0x9":   {'A9': ('L',), 'X19': ()},
        "9x0":   {'A9': ('L',), 'X19': ()},
        "10x10": {'A9': ('M',), 'X19': ()},
        "18x0":  {'A9': ('N',), 'X19': ('H',)},
        "15x6":  {'A9': (), 'X19': ('J',)},
        "6x15":  {'A9': (), 'X19': ('J',)},
        }

    purgetable = [
                    ('59', 'Purge pcr input...'),
                    ('55', 'Purge pcr output...'),
                    ('54', 'Purge sdi video error...'),
                    ('53', 'Purge ip input stats...'),
                    ('52', 'Purge ip output stats...'),
                    ('51', 'Purge ethernet stats...'),
                    ('50', 'Purge psi tx route table...'),
                    ('49', 'Purge anc tx route table...'),
                    ('45', 'Purge audio tx route table...'),
                    ('44', 'Purge video tx route table...'),
                    ('42', 'Purge 18x18 crosspoint...'),
                    ('41', 'Purge sdi anc loopout...'),
                    ('40', 'Purge sdi audio loopout...'),
                    ('39', 'Purge sdi video loopout...'),
                    ('38', 'Purge anc rx route table...'),
                    ('34', 'Purge audio rx route table...'),
                    ('33', 'Purge video rx route table...'),
                    ('31', 'Purge anc ip input...'),
                    ('23', 'Purge audio ip input...'),
                    ('21', 'Purge video ip input...'),
                    ('19', 'Purge psi ip output...'),
                    ('17', 'Purge anc ip output...'),
                    ('9', 'Purge audio ip output...'),
                    ('6', 'Purge video ip output...')
                ]

    def pull_firmware(self):
        """
            The IPG does not have a firmware varid, so we will have to use
            snmp to load the firmware

            1. Get the revision major
            2. Get the revision minor
            3. Get the build number
        """
        varids = (
              '3@i',    # Revision Major (e.g. "1")
              '4@i',    # Revision Minor (e.g. "0")
              '6@s',    # Build Number (e.g. "0452-App F")
        )
        httpOp = self.http_thread.get_cfgweb(self.IP, varids).result
        return '%s.%s.%s' % (httpOp.get('3@i', ''),
                             httpOp.get('4@i', ''),
                             httpOp.get('6@s', ''))

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
        # Upgrade firmware (file) and filepath
        self.firmware = None
        self.filename = None
        # Used for validation if the official device name is different on the firmware.
        self.results = device_info_object.results
        # IPG requires a login
        self.login()
        card_name = self.results.get('card_name')
        if card_name != 'None' and (card_name in self.X19List or card_name in self.A9List):
            # Set the name of the card, as well as the frame.
            self.name = card_name
        else:
            self.name = self.snmp.get('1.3.6.1.2.1.1.1.0', 'Not Found')
        # Get the mac address
        self.probe()

    def probe(self):
        """
            Pull the IPG's:
                Mac Address: Varid 402@s
                Product Feature Name: Varid 53.{0-20}@s
                Product Feature Supported: Varid 53.{0-20}@s

        """
        # Pull Mac Address
        op = self.http_thread.get_cfgjson(self.IP, ["402@s"]).result
        self.results['mac'] = op.get('402@s', '-')
        # Go through enabled features
        # product_feature_varids = [
        #                         '402.0@s', '402.1@s', '402.2@s', '402.3@s',
        #                         '402.4@s', '402.5@s', '402.6@s', '402.7@s',
        #                         '402.8@s', '402.9@s', '402.10@s',
        #                         '402.11@s', '402.12@s', '402.13@s',
        #                         '402.14@s', '402.15@s', '402.16@s',
        #                         '402.17@s', '402.18@s', '402.19@s']
        # product_features = self.http_thread.get_cfgjson(self.IP,
        #                                                 product_feature_varids).result

    def reboot(self, event=None):
        self.requests['reboot'] = self.http_thread.set_cfgweb(self.IP, {'96@i': 1})

    def validate_upgrade_firmware(self, filepath):
        """ This method will take apart the tar.gz file passed and will check what device is
            supported.
            1. Open the ciu file
            2. Check if util is in the name, expect the utils.tgz file.
                (checksum.md5, firmware.img, prod.regex and version.)
            3. Check that all of the files needed are present.
            4. Validate application.json. Pull Version & Device name
            5. Validate Imagelist.txt includes all files
                'img_checksums', 'application.json',
                'imagelist.txt', 'img_config', 'img_platform',
            # 6. TODO Validate that the checksom for the image is okay.
            # 7. Validate that the img_config file is present
            # 8. Validate that the img_platform file contains 570IPG
            # 9. Validate image version and expected version are the same.

            this method will set the self.upgrade_file field to contain the tar
            returns a touple (firmware_device, firmware_version)
            ex:
                firmware_device: '570IPG'
                firmware_version: '1.0.0_0864' ({version}_{build})
        """
        # These values will be populated later
        firmware_version = ""
        firmware_device = ""
        # Populated when looking through the .img file.
        # image_version = ""
        required_files = {'img_checksums': False, 'application.json': False,
                          'imagelist.txt': False, 'img_config': False,
                          'img_platform': False, }
        # Setting the firmware version as the filename.
        firmware_version = filepath
        # 1. Open the ciu file
        ciu_file = ZipFile(filepath)
        files_inside = ciu_file.infolist()
        # CUI Filename
        ciu_filename = filepath.split('\\')[-1]
        # Get the image name
        expected_image_name = f"{ciu_filename.replace('.ciu', '.img')}"
        if 'utils' in expected_image_name:
            expected_image_name = expected_image_name.replace('-utils', '')
        # Create the imagelist files
        imagelist = ['img_checksums', 'img_config',
                     'img_platform', expected_image_name]
        # 2. If util is in the name, expect the utils.tgz file.
        if 'util' in ciu_filename:
            # There are 6 files for the X-19
            if len(files_inside) > 6:
                required_files['utils.tgz'] = True

        # 3. Check that all of the files needed are present.
        for file in files_inside:
            data = ""
            # Pull filename and extract the file.
            filename = file.filename
            print(filename)
            # If the filename is utils just skip
            if 'utils' in filename:
                continue
            try:
                if expected_image_name in filename:
                    data = ciu_file.read(filename)
                else:
                    data = ciu_file.read(filename).decode('utf-8')
            except Exception:
                print('There was an issue extracting the data from '
                      'the ciu file. Invalid file given. file: '
                       f'{filename}.')
            # 4. Validate application.json. Pull Version & Device name
            if filename == 'application.json':
                # There should be an application.json file if X-19 card
                json_contents = json.loads(data)
                app = json_contents.get('app')
                date = app.get('date').replace('.', '')
                version = app.get('version')
                ver = version.replace('.', '')
                build = app.get('build', '').zfill(4)
                #firmware_version = 570IPG-X19-10G-V100B20221125-0864
                firmware_version = f"{self.name}-V{ver}B{date}-{build}"
                # firmware_device = 570IPG
                firmware_device = json_contents.get('device', {}).get('platform')
                if not firmware_device or not firmware_version:
                    raise ValueError("application.json does not populate"
                                     f"firmware_device or firmware_version."
                                     f"firmware_device: {firmware_device}"
                                     f"firmware_version:{firmware_version}")
                required_files[filename] = True
            # 5. Validate Imagelist.txt includes all files
            elif filename == 'imagelist.txt':
                # Check if everything expected is inside imagelist.txt
                for expected_file in imagelist:
                    if expected_file not in data:
                        raise ValueError("Imagelist does not have all of the "
                                         f"required files. Expected imagelist:"
                                         f"{imagelist}\nimagelist.txt: {data}")
                required_files[filename] = True
            # 6. TODO Validate that the checksom for the image is okay.
            elif filename == 'img_checksums':
                # Check if the firmware image name is in the checksum
                # expected_image_name = 570IPG-X19-10G-V100B20221125-0864-H.ciu
                cut_filename = expected_image_name.replace('.ciu', '.img')
                if cut_filename in data:
                    required_files[filename] = True
                else:
                    raise ValueError("img_checksums does not include"
                                     f"expected .img file name."
                                     f"expected_filename: {cut_filename}.")
            # 7. Validate that the img_config file is present
            elif filename == 'img_config':
                required_files[filename] = True
            # 8. Validate that the img_platform file contains 570IPG
            elif filename == 'img_platform':
                # Should contain the device model "570IPG"
                if data.strip() in expected_image_name:
                    required_files[filename] = True
                else:
                    raise ValueError("The device name was not found in the .cui"
                                     f"filename. ciu_filename:{expected_image_name}, "
                                     f"data:{data}.")
            # 9. Validate image version and expected version are the same. (.img)
            elif expected_image_name in filename:
                # firmware_version: 570IPG-X19-10G-V100B20221125-0864
                # image_version: 570IPG-X19-10G-20221125-0864 (without V100B)
                # Check if the firmware version is in the image
                # Remove the version from the firmware name
                cut_firmware = re.sub(r"V[0-9]*B", '', firmware_version)
                # take out the build number due to
                split_firmware = cut_firmware.split('-')
                firmware_build = split_firmware.pop()
                # If the firmware is only 3 number long add a 0 infront
                while len(firmware_build) < 4:
                    # Add a leading 0
                    firmware_build = '0' + firmware_build
                split_firmware.append(firmware_build)
                cut_firmware = '-'.join(split_firmware)
                # cut_firmware: 570IPG-X19-10G-20210421-0753
                if bytes(cut_firmware, 'utf-8') in data:
                    required_files[filename] = True
                else:
                    raise ValueError("The data inside of the .img file should "
                                     f"include the \n<device_name>-<date>-<build>."
                                     "\nExample: 570IPG-X19-10G-20221125-0864.\n"
                                     f" expected:{cut_firmware} but the .img"
                                     f"does not include this.")
            else:
                print("WARNING: There was an extra file found which we did "
                      f"not expect! file: {filename} ")
        # Check if firmware_build includes
        # We expect the firmware to include most of the .img
        if firmware_version not in filepath:
            # firmware_version:570IPG-X19-10G-V100B20221125-0864
            # filepath:/path/to/file/570IPG-X19-10G-V100B20221125-0864-H.img
            raise ValueError("The Version that we expected is not the version"
                             "that the .img file has as its name.\n"
                             f"firmware_version:{firmware_version} not in "
                             f"filepath:{filepath}")
        if False in list(required_files.values()):
            raise ValueError("One of the files that are required were not "
                             "found. required_files: %s" % (required_files))
        return (firmware_device, firmware_version)

    def upgrade(self, filepath):
        '''
        Initiates an upgrade of the device with the given 'image_dict'
        and its originating 'filename' (stripped of path).
        Can possibly spawn a new thread, or perform upgrade
        during poll_upgrade() calls.
        Does not block. Returns right away.
        If the image is not suitable, raise an exception
        in the next poll_upgrade() call.

        X-19 IPG

        All IPG upgrades include files:
            img_config, img_platform, img_checksums, application.json,
            imagelist.txt, <image file>.img

        Steps:

        '''
        self.flags.update({'uploadFinished': False, 'upgradeFinished': False,
                           'cleandiskFinished': False, 'upgradeError': False,
                           'upgradeActive': False})
        self.image_path = filepath
        self.firmware = open(filepath, 'rb')
        cui_filename = filepath.split('\\')[-1]
        self.requests = {}
        self.restart_snmp_threads()
        # Pull Firmware for comparison before & after upgrade.
        firmware_before_upgrade = self.pull_firmware()
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
        # 1. Get the size of the file and store it in the device if its suppoerted
        firmware_size = len(self.firmware.read())
        # Open up the ciu file and go through the files individually
        files = {}
        ciu_file = ZipFile(filepath)
        files_inside = ciu_file.infolist()
        for file in files_inside:
            inside_filename = file.filename
            # Go through each file and pull the size and data.
            file_data = ciu_file.read(inside_filename)
            # file_size = len(file_data)
            # Populate files for later use.
            files[inside_filename] = file_data
        # 2. Create some room for the upgrade to take place
        # IPG's use the url /v.1.5/php/features/feature-upgrade-agent-action.php
        feature_action = 'feature-upgrade-agent-action.php'
        # GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=cleandisk&size=53479693
        self.requests['cleardisk_platform'] = get_cleandisk(self.http_thread,
                                                            str_https,
                                                            self.IP,
                                                            firmware_size,
                                                            self.webeasy_version,
                                                            feature_action=feature_action)
        # 3. Upload the img_platorm file
        # POST /v.1.5/php/features/feature-transfer-upload.php?filename=img_platform
        request_filename = 'img_platform'
        # files = {filename: data}
        data = files.get(request_filename)
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['upload-img_platform'] = post_upload_file(self.http_thread,
                                                                str_https,
                                                                self.IP,
                                                                request_filename,
                                                                self.webeasy_version,
                                                                data)
        # 4. Loghash img_platform
        # GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=loghash&filename=img_platform&date=1692191481164
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['loghash-img_platform1'] = get_loghash(self.http_thread,
                                                             str_https,
                                                             self.IP,
                                                             request_filename,
                                                             self.webeasy_version,
                                                             feature_action=feature_action)

        # 5. Execute img_platform
        # GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=execute&filename=img_platform&date=1692191481962
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['execute-img_platform'] = get_execute_file(self.http_thread,
                                                                 str_https,
                                                                 self.IP,
                                                                 request_filename,
                                                                 self.webeasy_version,
                                                                 feature_action=feature_action)
        # 6. Loghash img_platform
        # GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=loghash&filename=img_platform&date=1692191502164
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['loghash-img_platform2'] = get_loghash(self.http_thread,
                                                             str_https,
                                                             self.IP,
                                                             request_filename,
                                                             self.webeasy_version,
                                                             feature_action=feature_action)
        # 7. Upload the img_config file the device
        # POST /v.1.5/php/features/feature-transfer-upload.php?filename=img_config
        request_filename = 'img_config'
        # files = {filename: data}
        data = files.get(request_filename)
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['upload-img_config'] = post_upload_file(self.http_thread,
                                                              str_https, self.IP,
                                                              request_filename,
                                                              self.webeasy_version,
                                                              data)
        # 8. Convert the uploaded file to a loghash
        #   GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=loghash&filename=img_config&date=1684271693128
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['loghash-img_config1'] = get_loghash(self.http_thread,
                                                           str_https,
                                                           self.IP,
                                                           request_filename,
                                                           self.webeasy_version,
                                                           feature_action=feature_action)
        # 9. Execute the upgrade
        #   GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=execute&filename=img_config&date=1684271693595
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['execute-img_config'] = get_execute_file(self.http_thread,
                                                               str_https,
                                                               self.IP,
                                                               request_filename,
                                                               self.webeasy_version,
                                                               feature_action=feature_action)
        # 10. Do a loghash on the img_config
        #   GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=loghash&filename=img_config&date=1684271713797
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['loghash-img_config2'] = get_loghash(self.http_thread,
                                                           str_https,
                                                           self.IP,
                                                           request_filename,
                                                           self.webeasy_version,
                                                           feature_action=feature_action)
        # 11. Upload the img_checksums file
        #   POST /v.1.5/php/features/feature-transfer-upload.php?filename=img_checksums
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        request_filename = 'img_checksums'
        data = files.get(request_filename)
        # files = {filename: data}
        self.requests['upload-img_checksums'] = post_upload_file(self.http_thread,
                                                                 str_https,
                                                                 self.IP,
                                                                 request_filename,
                                                                 self.webeasy_version,
                                                                 data)
        # . Do a loghash on the img_checksums file
        #   GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=loghash&filename=img_checksums&date=1684271714974
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['loghash-img_img_checksums1'] = get_loghash(self.http_thread,
                                                                  str_https,
                                                                  self.IP,
                                                                  request_filename,
                                                                  self.webeasy_version,
                                                                  feature_action=feature_action)
        # 9. Execute the img_checksum file
        #   GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=execute&filename=img_checksums&date=1684271715571
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['execute-img_checksums'] = get_execute_file(self.http_thread,
                                                                  str_https,
                                                                  self.IP,
                                                                  request_filename,
                                                                  self.webeasy_version,
                                                                  feature_action=feature_action)
        # 10. Do a loghash on the img_checksum file
        # #   GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=loghash&filename=img_checksums&date=1684271735773
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['loghash-img_checksums2'] = get_loghash(self.http_thread,
                                                              str_https,
                                                              self.IP,
                                                              request_filename,
                                                              self.webeasy_version,
                                                              feature_action=feature_action)
        # If the firmware contains a utils file.
        if 'utils.tgz' in files.keys():
            # 11. Upload the utils file
            #   POST /v.1.5/php/features/feature-transfer-upload.php?filename=utils.tgz
            request_filename = 'utils.tgz'
            # files = {filename: data}
            data = files.get(request_filename)
            # Give it a little gap so time.time can change.
            time.sleep(0.2)
            self.requests['upload-utils'] = post_upload_file(self.http_thread,
                                                             str_https,
                                                             self.IP,
                                                             request_filename,
                                                             self.webeasy_version,
                                                             data)
            # 12. Loghash on the utils file
            #   GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=loghash&filename=utils.tgz&date=1684271742424
            # Give it a little gap so time.time can change.
            time.sleep(0.2)
            self.requests['loghash-utils'] = get_loghash(self.http_thread,
                                                         str_https,
                                                         self.IP,
                                                         request_filename,
                                                         self.webeasy_version,
                                                         feature_action=feature_action)
            # 13. Execute the utils.tgz file
            #   GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=execute&filename=utils.tgz&date=1684271743091
            # Give it a little gap so time.time can change.
            time.sleep(0.2)
            self.requests['execute-utils'] = get_execute_file(self.http_thread,
                                                              str_https,
                                                              self.IP,
                                                              request_filename,
                                                              self.webeasy_version,
                                                              feature_action=feature_action)
            # 14. Loghash the utils file
            #   GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=loghash&filename=utils.tgz&date=1684271763298
            # Give it a little gap so time.time can change.
            time.sleep(0.2)
            self.requests['loghash-utils'] = get_loghash(self.http_thread,
                                                         str_https,
                                                         self.IP,
                                                         request_filename,
                                                         self.webeasy_version,
                                                         feature_action=feature_action)
        # 15. Upload the firmware file (.img)
        #   POST /v.1.5/php/features/feature-transfer-upload.php?filename=570IPG-X19-10G-V100B20210421-0753-F.img
        # Replace .ciu with .img the filename
        print(f"DEBUG:filename:{cui_filename}\n")
        request_filename = cui_filename.replace('.ciu', '.img').replace('-utils', '')
        data = files.get(request_filename)
        print(f"DEBUG: request_filename:{request_filename}, filename:{cui_filename}\n")
        print(f"DEBUG: len data:{len(data)}\n")

        time.sleep(10)
        # files = {filename: data}
        self.requests['upload-img'] = post_upload_file(self.http_thread,
                                                       str_https, self.IP,
                                                       request_filename,
                                                       self.webeasy_version,
                                                       data)
        # 16. Loghash the firmware file (.img)
        #   GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=loghash&filename=570IPG-X19-10G-V100B20210421-0753-F.img&date=1684271823707
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['loghash-img'] = get_loghash(self.http_thread,
                                                   str_https,
                                                   self.IP,
                                                   request_filename,
                                                   self.webeasy_version,
                                                   feature_action=feature_action)
        # 17. Execute the firmware file
        #   GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=execute&filename=570IPG-X19-10G-V100B20210421-0753-F.img&date=1684271824198
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['execute-img'] = get_execute_file(self.http_thread,
                                                        str_https,
                                                        self.IP,
                                                        request_filename,
                                                        self.webeasy_version,
                                                        feature_action=feature_action)
        # 16. Loghash the firmware file (.img)
        # GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=loghash&filename=570IPG-3G18-SFPP12-V110B20200106-1705-J.img&date=1692191640548
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['loghash-img1'] = get_loghash(self.http_thread,
                                                   str_https,
                                                   self.IP,
                                                   request_filename,
                                                   self.webeasy_version,
                                                   feature_action=feature_action)
        # 19. Execute the reboot/ Indicate that the process is done
        # GET /v.1.5/php/features/feature-upgrade-agent-action.php?action=execute&filename=done&date=1692191640758
        # Give it a little gap so time.time can change.
        time.sleep(0.2)
        self.requests['execute-img'] = get_execute_file(self.http_thread,
                                                        str_https,
                                                        self.IP,
                                                        "done",
                                                        self.webeasy_version,
                                                        feature_action=feature_action)

        print("Completed Upgrade. Waiting for reboot")
        # self.reboot()
        # 18. Wait 3 minutes and then validate that it is upgraded. (Maybe a reboot here.)
        time.sleep(160)
        # Validate that the upgrade was done properly
        # Pull Firmware for comparison before & after upgrade.
        firmware_after_upgrade = self.pull_firmware()
        print(f'DEBUG: firmware_before_upgrade == firmware_after_upgrade:\n {firmware_before_upgrade} == {firmware_after_upgrade}')
        if firmware_before_upgrade == firmware_after_upgrade:
            comment = ("Warning: The firmware before the upgrade was not the "
                       "same as the firmware after the upgrade. "
                       f"Firmware before upgrade:{firmware_before_upgrade}\n"
                       f"Firmware after upgrade:{firmware_after_upgrade}")
            print(comment)
            self.flags['upgradeError'] = comment
        # Finish the upgrade.
        self.flags['upgradeFinished'] = True

    # if firmware_version:
        #         if '570IPG-X19-25G' in ciu_filename:
        #             if self.live['name'] in self.A9List:
        #                 raise ValueError('Expected A9 firmware, got 25G')
        #             elif '570IPG-X19-25G' not in self.live['name']:
        #                 raise ValueError('Expected X19 firmware, got 25G')
        #         elif '570IPG-X19' in ciu_filename:
        #             if self.live['name'] in self.A9List:
        #                 raise ValueError('Expected A9 firmware, got X19')
        #             elif '570IPG-X19-25G' in self.live['name']:
        #                 raise ValueError('Expected A9 firmware, got 25G')
        #         elif '570IPG' in ciu_filename and 'SFPP12' in ciu_filename:
        #             if self.live['name'] not in self.A9List:
        #                 raise ValueError('Expected X19 firmware, got A9')
        #             elif '570IPG-X19-25G' in self.live['name']:
        #                 raise ValueError('Expected X19 firmware, got 25G')
        #     else:
        #         self.errors.append('Image filename not found')
        #         raise ValueError('Image file not found within .ciu file!')
