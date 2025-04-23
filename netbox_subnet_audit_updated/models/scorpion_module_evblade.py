import tarfile
from zipfile import ZipFile
import json
# from models.scorpion_module import ScorpionModule
import models.scorpion_module

class ScorpionModule(models.scorpion_module.ScorpionModule):
    """
        This class is created to store Scorpion Frame objects.
        This class overwrites methods:
            'validate_upgrade_firmware' method will validate that the firmware
                file passed has all of the required files needed to upgrade
                properly.
    """
    GROUP = "SCORPION MODULE"
    VALIDATED_MODULE_LIST = ["MIO-APP-XS-2E2D", "MIO-APP-XS-1E3D",
                             "MIO-APP-XS-3E1D", "MIO-APP-UDX-3G",
                             "MIO-APP-UDX-4K", "MIO-APP-CCE",
                             "MIO-APP-IPG-ST2110-AES", "MIO-APP-IPG-ST2022",
                             "MIO-APP-IPG-ST2022-A", "MIO-APP-IPG-ST2022-B"
                             "MIO-APP-IPG-ST2110", "MIO-APP-IPG-ST2110-A",
                             "MIO-APP-IPG-ST2110-B", "MIO-APP-DLY",
                             "MIO-APP-DLY2"]

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

    def validate_upgrade_firmware(self, filepath):
        """ This method will take apart the tar.gz file passed and will check what device is
            supported.
            Files: application.json, imagelist.txt,  firmware.tar.gz
            Difference in application.json
            hardware.fpga.name:
                possible names:
                            "MIO-APP-UDX-3G",
                            "MIO-APP-UDX-4K",
                            "MIO-APP-2QUAD",
                            "MIO-APP-CCE",
                            "MIO-APP-DLY2",
                            "MIO-APP-J2K-2E",
                            "MIO-APP-J2K-2D",
                            "MIO-APP-J2K-1D1E",
                            "MIO-APP-XS",
                            "MIO-APP-IPG"

                            MIO-APP-IPG-2110
            Inside firmware.tar.gz:
                build_info.conf: The same throughout...
                bundle_package.tar: Not worth looking through
                checksum.md5: bundle_package.tar, image.ub
                image.ub
                post_upgrade.sh (same throughout)
                pre_upgrade.sh (same throughout)
                prod.regex: '^PROD=(EMMC-)?MIO[-]?BLADE.*$' on all of mio blades
            /imagelist.txt, MIO-AES-IN6-OUT6.img,  MIO-AES-IN6-OUT6.img.md5, product.json
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
        # supported = False
        required_files = {'imagelist.txt': False, 'application.json': False,
                          'firmware.tar.gz': False}
        # The files inside of firmware.tar.gz
        expected_firmware_files = ["build_info.conf", "bundle_package.tar",
                                   "prod.regex", "checksum.md5", "image.ub",
                                   "post_upgrade.sh", "pre_upgrade.sh"]
        # The filenames expected inside of the imagelist.txt
        imagelist = ['firmware.tar.gz']
        # The possible names of modules inside of the application.json(app.name)
        application_json = ["mio-app-cc", "mio-app-dly2", "mio-ipg-aes",
                            "mio-app-ipg-2022", "mio-app-ipg-2110"]
        # Setting the firmware version as the filename.
        firmware_version = filepath
        # 1. Open the ciu file
        ciu_file = ZipFile(filepath)
        files_inside = ciu_file.infolist()
        # 2. Check that all of the files needed are present.
        for file in files_inside:
            # Pull filename and extract the file.
            filename = file.filename
            # # 4. Check that the prod.regex file has 'SCORPION' as the only field inside
            if filename == 'application.json':
                try:
                    data = ciu_file.read(filename).decode('utf-8')
                    # Convert the json to dict
                    image_dict = json.loads(data)
                    # Look through the data and pull the image name and version.
                    app = image_dict.get('app')
                    firmware_device = app.get('name')
                    firmware_version = app.get('version')
                    if (firmware_device.lower() in application_json and
                            firmware_device.lower() in self.name.lower()):
                        # It is a valid evblade module Should cover all cases...
                        required_files[filename] = True
                except Exception:
                    print('There was an issue extracting the data from '
                          'the ciu file. Invalid file given. file: '
                           f'{filename}')
                print(f"firmware_device:{firmware_device}, firmware_version:{firmware_version}")
                required_files[filename] = True
            elif filename == 'imagelist.txt':
                try:
                    data = ciu_file.read(filename).decode('utf-8')
                except Exception:
                    print('There was an issue extracting the data from '
                          f'file: "{filename}"')
                # Check if everything expected is inside imagelist.txt
                for expected_file in imagelist:
                    if expected_file not in data:
                        raise ValueError("One of the files that are required " +
                                         "were not found. required_files:" +
                                         f"{required_files}")
                required_files[filename] = True
            elif filename == 'firmware.tar.gz':
                # Open up the .tar.gz file.
                data = ciu_file.extract(filename)
                tar = tarfile.open(data, 'r:gz')
                firmware_inside = tar.getmembers()
                # Check if all expected files are inside and accounted
                for tar_file in firmware_inside:
                    tarfile_name = tar_file.name
                    if tarfile_name not in expected_firmware_files:
                        raise ValueError("One of the files that are required " +
                                         "were not found in the folder:" +
                                         f"{filename}. tarfile:{tarfile_name} " +
                                         "Missing file:" +
                                         f"{expected_firmware_files}, " +
                                         "required_files:" +
                                         f"{expected_firmware_files}")
                required_files[filename] = True
            else:
                raise ValueError("There was a problem validating the "
                                 "'application.json' file. It does not "
                                 "have 'SCORPION' in the file."
                                 f"Data: {data}")
        if False in list(required_files.values()):
            raise ValueError("One of the files that are required were not "
                             f"found. required_files: {required_files}")
        return (firmware_device, firmware_version)


# ciu_file = ZipFile(filepath)
# files_inside = ciu_file.infolist()
# for file in files_inside:
#     filename = file.filename
#     if filename == 'firmware.tar.gz':
#         # data = ciu_file.read(filename)
#         data = ciu_file.extract(filename)
#         tar = tarfile.open(data, 'r:gz')
#         firmware_inside = tar.getmembers()
#         for a in firmware_inside:
#             print(a)

