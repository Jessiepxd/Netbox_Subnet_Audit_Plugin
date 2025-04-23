import tarfile
import re
# from models.scorpion_module import ScorpionModule
import models.scorpion_module

class ScorpionModule(models.scorpion_module.ScorpionModule):
    """
        This class is created to store Scorpion Frame objects.
        This class overwrites :
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

        NOTE: This device is exactly the same as the defualt mio upgrade,
              But has three extra firmware files as well as 3 firmware.md5
              when validating if the device is able to be upgraded.
    """
    GROUP = "SCORPION MODULE"
    # List of devices that this module supports
    VALIDATED_MODULE_LIST = ["MIO_HDMI_2_4K_IP"]

    def __init__(self, scorpion_frame_obj, module_name: str,
                 module_slot: int, validation_device_name=''):
        """
        The init method will initialize the scorpion object.
        It will probe the device for the modules and populate 'card_name',
        'webVerList'

        expected_device_name: The name which is used by the prod.regex file
                              to validate that the device supports it.
                              example: 'MIO-DX'
        module_name: The name of the scorpion module <str>
        module_slot: The slot the module resides in <int>


        Note: Upgrade is the same as scorpion_module.py
        """
        super().__init__(scorpion_frame_obj, module_name, module_slot,
                         validation_device_name)

    def validate_upgrade_firmware(self, filepath):
        """ This method will take apart the tar.gz file passed and will check what device is
            supported.
            1. Open the tar.gz file
            2. Check that all of the files needed are present.
                (checksum.md5, firmware.img, prod.regex and version.)
            3. Check that checksome contains a file inside called 'firmware.img'
            4. Check that the prod.regex file has '3606AVR' as the only field inside
            5. Check that the version file has a proper version inside the file.?
            6. Check that checksome contains a file inside called 'prod.regex'
            7. Check that there are three firmware md5 checksums
            8. Check that there are three firmware.img files.

            required_files = {'checksum.md5', 'firmware.img'
                          'prod.regex', 'version', 'firmware.md5'}

            this method will set the self.upgrade_file field to contain the tar
            returns a touple (firmware_device, firmware_version)
            ex:
                firmware_device: '3606AVR'
                firmware_version: 'Version 1.0 build 137'
            NOTE: Same like scorpion_module, but has two .md5 files...
        """
        # supported = False
        required_files = {'firmware1.img': False, 'firmware2.img': False,
                          'firmware3.img': False, 'firmware1.md5': False,
                          'firmware2.md5': False, 'firmware3.md5': False,
                          'checksum.md5': False, 'prod.regex': False,
                          'version': False, 'product': False}


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
                if 'prod.regex' in data:
                    required_files[filename] = True
                else:
                    raise ValueError("There was a problem validating the "
                                     "'checksum.md5' file. checksum.md5 "
                                     "could not find the img checksome. "
                                     "Data: %s" % (data))
            # 4. Check that the prod.regex file has 'SCORPION' as the only field inside
            elif filename == 'prod.regex' and file.isfile():
                # check that the file contains the proper information
                data = extracted_file.read().decode('utf8').strip()
                firmware_device = data
                if self.name in data or self.validation_device_name:
                    required_files[filename] = True
                else:
                    raise ValueError("There was a problem validating the "
                                     "'prod.regex' file. prod.regex does not "
                                     f"have '{self.name}' in the "
                                     "file. Data: %s" % (data))
            # 5. Check that the version file has a proper version inside the file.?
            elif filename == 'version' and file.isfile():
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
            # 6. Check that checksome contains a file inside called 'prod.regex'
            elif filename == 'checksum.md5' and file.isfile():
                data = extracted_file.read().decode('utf8').strip()
                if 'firmware.img' in data:
                    required_files[filename] = True
                else:
                    raise ValueError("There was a problem validating the "
                                     "'checksum.md5' file. checksum.md5 "
                                     "could not find the img checksome. "
                                     "Data: %s" % (data))
            # 6. Check that checksome contains a file inside called 'prod.regex'
            elif filename == 'firmware1.md5' and file.isfile():
                data = extracted_file.read().decode('utf8').strip()
                if 'firmware1.img' in data:
                    required_files[filename] = True
                else:
                    raise ValueError("There was a problem validating the "
                                     "'firmware1.md5' file. firmware1.md5 "
                                     "could not find the img checksome. "
                                     "Data: %s" % (data))
            elif filename == 'firmware2.md5' and file.isfile():
                data = extracted_file.read().decode('utf8').strip()
                if 'firmware2.img' in data:
                    required_files[filename] = True
                else:
                    raise ValueError("There was a problem validating the "
                                     "'firmware2.md5' file. firmware2.md5 "
                                     "could not find the img checksome. "
                                     "Data: %s" % (data))
            elif filename == 'firmware3.md5' and file.isfile():
                data = extracted_file.read().decode('utf8').strip()
                if 'firmware3.img' in data:
                    required_files[filename] = True
                else:
                    raise ValueError("There was a problem validating the "
                                     "'firmware3.md5' file. firmware3.md5 "
                                     "could not find the img checksome. "
                                     "Data: %s" % (data))
            elif filename == 'firmware1.img' and file.isfile():
                required_files[filename] = True
            elif filename == 'firmware2.img' and file.isfile():
                required_files[filename] = True
            elif filename == 'firmware3.img' and file.isfile():
                required_files[filename] = True
        if False in list(required_files.values()):
            raise ValueError("One of the files that are required were not "
                             "found. required_files: %s" % (required_files))
        return (firmware_device, firmware_version)