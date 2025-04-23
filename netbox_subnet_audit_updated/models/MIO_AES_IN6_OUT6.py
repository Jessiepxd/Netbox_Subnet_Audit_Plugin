from zipfile import ZipFile
# from models.scorpion_module import ScorpionModule
import models.scorpion_module

class ScorpionModule(models.scorpion_module.ScorpionModule):
    """
        This class is created to store Scorpion Frame objects.
        This class overwrites:
            'validate_upgrade_firmware' method will validate that the firmware
                file passed has all of the required files needed to upgrade
                properly.

        NOTE: This class is created to support validation using
              .CIU (zip) file formats.


    """
    GROUP = "SCORPION MODULE"
    # List of devices that this module supports
    VALIDATED_MODULE_LIST = ["MIO-AES-IN6-OUT6", "MIO-SRG", ]

    def __init__(self, scorpion_frame_obj, module_name: str,
                 module_slot: int, validation_device_name: str):
        """
        The init method will initialize the scorpion object.
        It will probe the device for the modules and populate 'card_name',
        'webVerList'
        module_name: The name of the scorpion module <str>
        module_slot: The slot the module resides in <int>


        Note: Upgrade is the same as scorpion_module.py
        """
        super().__init__(scorpion_frame_obj, module_name, module_slot,
                         validation_device_name)

    def validate_upgrade_firmware(self, filepath):
        """ This method will take apart the tar.gz file passed and will check what device is
            supported.
            /imagelist.txt, MIO-AES-IN6-OUT6.img,  MIO-AES-IN6-OUT6.img.md5, product.json
            1. Open the tar.gz file
            2. Check that all of the files needed are present.
                (MIO-AES-IN6-OUT6.img.md5, MIO-AES-IN6-OUT6.img, product.json
                and imagelist.txt)
            3. Check that checksome contains a file inside called 'MIO-AES-IN6-OUT6.img'
            4. Check that the product.json file has 'MIO-AES-IN6-OUT6' as the only field inside
            5. Check that the version file has a proper version inside the file.?

            this method will set the self.upgrade_file field to contain the tar
            returns a touple (firmware_device, firmware_version)
            ex:
                supported: True if supported, raises valueError if not supported
                firmware_device: 'SCORPION-6'
                firmware_version: 'Version 1.0 build 137'

            NOTE: Supports .ciu files
        """
        # supported = False
        required_files = {f'{self.name}.img.md5': False,
                          f'{self.name}.img': False,
                          'imagelist.txt': False, 'product.json': False}
        imagelist = [f"{self.name}.img.md5", "product.json",
                     f"{self.name}.img"]
        # Setting the firmware version as the filename.
        firmware_version = filepath
        # 1. Open the ciu file
        ciu_file = ZipFile(filepath)
        files_inside = ciu_file.infolist()
        # 2. Check that all of the files needed are present.
        for file in files_inside:
            # Pull filename and extract the file.
            filename = file.filename
            try:
                data = ciu_file.read(filename).decode('utf-8')
            except Exception:
                print('There was an issue extracting the data from '
                        'the ciu file. Invalid file given. file: '
                        f'{filename}')
            # 3. Check that checksome contains a file inside called 'firmware.img'
            if filename == f'{self.name}.img.md5':
                if f'{self.name}.img' in data:
                    required_files[filename] = True
                else:
                    raise ValueError("There was a problem validating the "
                                        f"'{self.name}.img.md5' file. File"
                                        "could not find the img checksum. "
                                        "Data: %s" % (data))
            # 4. Check that the prod.regex file has 'SCORPION' as the only field inside
            if filename == 'product.json':
                # check that the file contains the proper information
                firmware_device = data
                if f'{self.name}' in data:
                    required_files[filename] = True
                else:
                    raise ValueError("There was a problem validating the "
                                        "'prod.regex' file. prod.regex does not "
                                        "have 'SCORPION' in the file. "
                                        f"Data: {data}")
            if filename == 'imagelist.txt':
                # Check if everything expected is inside imagelist.txt
                for expected_file in imagelist:
                    if expected_file not in data:
                        raise ValueError("Imagelist does not have all of the "
                                         f"required files. Expected imagelist:"
                                         f"{imagelist}\nimagelist.txt: {data}")
                required_files[filename] = True
            if filename == f'{self.name}.img':
                required_files[filename] = True
        if False in list(required_files.values()):
            raise ValueError("One of the files that are required were not "
                f"found. required_files: {required_files}")
        return (firmware_device, firmware_version)