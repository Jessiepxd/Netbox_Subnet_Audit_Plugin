import tarfile
# from models.scorpion_module import ScorpionModule
import models.scorpion_module

class ScorpionModule(models.scorpion_module.ScorpionModule):
    """
        This class is created to store Scorpion Frame objects.
        This class overwrites methods:
            'validate_upgrade_firmware' method will validate that the firmware
                file passed has all of the required files needed to upgrade
                properly.

        Note: This class uses
    """
    GROUP = "SCORPION MODULE"
    VALIDATED_MODULE_LIST = ["MIO-APP-J2K-1E1D", "MIO-APP-J2K-2E",
                             "MIO-APP-J2K-2D"]

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

        Note: Upgrade is the same as scorpion_module.py
        """
        super().__init__(scorpion_frame_obj, module_name, module_slot,
                         validation_device_name)
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

    def validate_upgrade_firmware(self, filepath):
        """ This method will take apart the tar.gz file passed and will check what device is
            supported.
            Files:
                build_info.conf: The same throughout...
                bundle_package.tar: Not worth looking through
                checksum.md5: bundle_package.tar, image.ub
                image.ub
                post_upgrade.sh (same throughout)
                pre_upgrade.sh (same throughout)
                prod.regex: '^PROD=(EMMC-)?MIO[-]?BLADE.*$' on all of mio blades
            1. Open the tar.gz file
            2. Check that all of the files needed are present.
                (MIO-AES-IN6-OUT6.img.md5, MIO-AES-IN6-OUT6.img, product.json
                and imagelist.txt)
            3. Check that checksum contains a file inside called 'MIO-AES-IN6-OUT6.img'
            4. Check that the product.json file has 'MIO-AES-IN6-OUT6' as the only field inside
            5. Check that the version file has a proper version inside the file.?

            this method will set the self.upgrade_file field to contain the tar
            returns a tuple (firmware_device, firmware_version)
            ex:
                supported: True if supported, raises valueError if not supported
                firmware_device: 'SCORPION-6'
                firmware_version: 'Version 1.0 build 137'

            NOTE: Supports .ciu files
        """
        # The files inside of firmware.tar.gz
        required_files = {"build_info.conf": False, "bundle_package.tar": False,
                          "prod.regex": False, "checksum.md5": False,
                          "image.ub": False, "post_upgrade.sh": False,
                          "pre_upgrade.sh": False}
        expected_firmware_files = ["bundle_package.tar",
                                   "prod.regex", "image.ub",
                                   "post_upgrade.sh", "pre_upgrade.sh"]
        # Setting the firmware version as the filename.
        firmware_version = filepath
        # The name of the expected device to be upgraded. ex.'MIO-APP-IPG-2110'
        firmware_device = ""
        # 1. Open the tar.gz file
        tar = tarfile.open(str(filepath), 'r:gz')
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
                # includes fpga.bit and image.ub
                if "fpga.bit" in data and "image.ub" in data:
                    required_files[filename] = True
            elif filename == "build_info.conf":
                data = extracted_file.read().decode('utf8').strip()
                if "REL_NAME=MIO-BLADE" in data:
                    required_files[filename] = True
            elif filename in expected_firmware_files:
                # These are all the same or are not worth looking through.
                required_files[filename] = True
            else:
                raise ValueError("There was a problem validating the "
                                 f"file: '{filename}'. File not found in the"
                                 f"Required files: {required_files}."
                                 f"")
        if False in list(required_files.values()):
            raise ValueError("One of the files that are required were not "
                             f"found. required_files: {required_files}")
        return (firmware_device, firmware_version)

