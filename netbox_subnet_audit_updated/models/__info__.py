# Import models
import time

# import ipg570 as ipg570
# import vip10g
# import exe
# import bladez
# import magnumsdvn
# import ipg670
from models.scorpion_module import (Scorpion, ScorpionModule)

import models.MIO_AES_IN6_OUT6, models.MIO_CCE_AUX_IO, models.MIO_VB_2_12G
import models.scorpion_module_evblade, models.scorpion_module_evblade_j2k
import models.ipg570

# All the supported classes
# CLASSES = (ipg570.IPG570, vip10g.VIP10G, itxe570.ITXE570, rx2_2430.RX2_2430,
#            emr570.EMR570, exe.EXE,
#            fc570.FC570,
#            ipsr3080.IPSR3080,
#            bladez.BLADEZ, rx2_2430_j2k.RX2_2430_J2K, magnumsdvn.MAGNUMSDVN,
#            magnumch.MAGNUMCH, remtx570.REMTX570, remrx570.REMRX570,
#            j2k570.J2K570, emr570tdmts.EMR570TDMTS, madi3080ts.MADI3080TS,
#            ts3080madi.TS3080MADI, ipg670.IPG670, ipx3080.IPX3080,
#            scorpion.SCORPION, mma10g.MMA10G,
#            msc5601.MSC5601, msc5700ip.MSC5700IP)
# Mapping of GROUP name to class
# GROUPS = {cls.GROUP.upper(): cls for cls in CLASSES}

def create_scorpion_module(frame, module_name, module_slot):
    """
        This method will return a scorpion module based on the frame and
        module name passed

        Parameters:
            frame: Scorpion object containing the frame information
            module_name: The Module name that we are looking at.
    """
    if "scorpion" not in frame.name.lower():
        print("Failed to validate Frame name as scorpion. frame_name:"
              f"{frame.name.lower()} module:{module_name}, slot:{module_slot}")
        return None
    if module_name == '' or module_name == None or module_name == 'None':
        print("Failed module name not in supported module list. "
              f"module:{module_name}")
        return None
    # Check if module is not supported.
    if module_name not in frame.SUPPORTED_MODULE_LIST:
        # Still create a module, but skip other validation.
        print("Warning module name not in supported module list."
              f"Create default module. module:{module_name}")
        device = ScorpionModule(frame, module_name, module_slot, module_name)
        return device
    # Look through each module
    if module_name == "MIO-AVR":
        # print(f"DEBUG: Validated as MIO-AVR module:{module_name}, slot:{module_slot}")
        device = ScorpionModule(frame, module_name, module_slot,
                                validation_device_name="3606AVR")
    elif module_name == "MIO-AVT":
        # print(f"DEBUG: Validated as MIO-AVT module:{module_name}, slot:{module_slot}")
        device = ScorpionModule(frame, module_name, module_slot,
                                validation_device_name="3606AVT")
    elif module_name == "MIO-DANTE":
        # print(f"DEBUG: Validated as MIO-DANTE module:{module_name}, slot:{module_slot}")
        device = ScorpionModule(frame, module_name, module_slot,
                                validation_device_name="3606DANTE")
    elif module_name == "MIO-AES-D4":
        # print(f"DEBUG: Validated as MIO-AES-D4 module:{module_name}, slot:{module_slot}")
        device = ScorpionModule(frame, module_name, module_slot,
                                validation_device_name="3606AES-D4")
    elif module_name == "MIO-DM-TRK-SA":
        # print(f"DEBUG: Validated as MIO-DM-TRK-SA module:{module_name}, slot:{module_slot}")
        device = ScorpionModule(frame, module_name, module_slot,
                                validation_device_name="MIO-DM-TRK-SA")
    elif module_name in ("MIO-HDMI-IN1-4K-IP",
                         "MIO-HDMI-OUT-4K-IP", "MIO-HDMI-OUT1-4K-IP"):
        # print(f"DEBUG: Inside MIO-HDMI-X1-4K-IP. module:{module_name}, slot:{module_slot}")
        device = ScorpionModule(frame, module_name, module_slot,
                                validation_device_name="MIO-HDMI-4K-IP")
    elif module_name == "MIO-HDMI-IN-3G":
        # print(f"DEBUG: Validated as MIO-HDMI-IN-3G module:{module_name}, slot:{module_slot}")
        device = ScorpionModule(frame, module_name, module_slot,
                                validation_device_name="3606HDMI-3GT")
    elif module_name == "MIO-HDMI-2-4K-IP":
        # print(f"DEBUG: Validated as MIO-HDMI-2-4K-IP module:{module_name}, slot:{module_slot}")
        device = ScorpionModule(frame, module_name, module_slot,
                                validation_device_name="MIO-HDMI-2")
    elif module_name == "MIO-IT-IP":
        # print(f"DEBUG: Validated as MIO-IT-IP module:{module_name}, slot:{module_slot}")
        device = ScorpionModule(frame, module_name, module_slot,
                                validation_device_name="3606-IT2")
    elif module_name == "MIO-MADI-2-IP":
        # print(f"DEBUG: Validated as MIO-MADI-2-IP module:{module_name}, slot:{module_slot}")
        device = ScorpionModule(frame, module_name, module_slot,
                                validation_device_name="MIO-MADI-2-IP")
    elif module_name == "MIO-HDMI-OUT-3G":
        # print(f"DEBUG: Validated as MIO-HDMI-OUT-3G module:{module_name}, slot:{module_slot}")
        device = ScorpionModule(frame, module_name, module_slot,
                                validation_device_name="3606HDMI-3GR")
    elif module_name in ("MIO-USB-A", "MIO-USB-B"):
        # print(f"DEBUG: Validated as MIO-USB module:{module_name}, slot:{module_slot}")
        device = ScorpionModule(frame, module_name, module_slot,
                                validation_device_name="MIO-USB")
    # Device has an extra .md5 checksum
    elif module_name in ("MIO-XPS", "MIO-VTR-2-12G", "MIO-VB-2-12G",
                         "MIO-SFP", "MIO-HDMI-OUT-4K", "MIO-HDMI-IN-4K",
                         "MIO-GE-RJ45"):
        # print(f"Validated as MIO-VB-2-12G module:{module_name}, slot:{module_slot}")
        device = models.MIO_VB_2_12G.ScorpionModule(frame, module_name,
                                                    module_slot)
    elif (module_name in ("MIO-AES-IN6-OUT6", "MIO-SRG")):
        # print(f"Validated as MIO-AES-IN6-OUT6. module:{module_name}, slot:{module_slot}")
        device = models.MIO_AES_IN6_OUT6.ScorpionModule(frame, module_name,
                                                        module_slot,
                                                        module_name)
    elif (module_name in ("MIO-DD4-3G", "MIO-DE4-3G", "MIO-CCE-AUX-IO")):
        # print(f"Validated as MIO-CCE-AUX-IO. module:{module_name}, slot:{module_slot}")
        device = models.MIO_CCE_AUX_IO.ScorpionModule(frame, module_name,
                                                      module_slot,
                                                      "MIO-DX")
    elif module_name == "MIO-HDMI-2-4K-IP":
        # print(f"Validated as MIO-HDMI-2-4K-IP module:{module_name}, slot:{module_slot}")
        device = models.MIO_HDMI_2_4K_IP.ScorpionModule(frame, module_name,
                                                        module_slot,
                                                        "MIO-HDMI-2")
    elif module_name in ("MIO-APP-XS-2E2D", "MIO-APP-XS-1E3D",
                         "MIO-APP-XS-3E1D", "MIO-APP-UDX-3G",
                         "MIO-APP-UDX-4K", "MIO-APP-CCE",
                         "MIO-APP-DLY", "MIO-APP-DLY2",
                         "MIO-APP-IPG-ST2110-AES", "MIO-APP-IPG-ST2022",
                         "MIO-APP-IPG-ST2022-A", "MIO-APP-IPG-ST2022-B"
                         "MIO-APP-IPG-ST2110", "MIO-APP-IPG-ST2110-A",
                         "MIO-APP-IPG-ST2110-B",):
        print(f"Validated EVBLADE. module:{module_name}, slot:{module_slot}")
        device = models.scorpion_module_evblade.ScorpionModule(frame,
                                                               module_name,
                                                               module_slot,
                                                               module_name)
    elif module_name in ("MIO-APP-J2K-1E1D", "MIO-APP-J2K-2E",
                         "MIO-APP-J2K-2D"):
        print(f"DEBUG: Validated EVBLADE J2K. module:{module_name}, slot:{module_slot}")
        device = models.scorpion_module_evblade_j2k.ScorpionModule(frame,
                                                                   module_name,
                                                                   module_slot,
                                                                   module_name)
    # elif module_name in ("MIO-AES-D4", "MIO-AES-LTC-D4", "MIO-AES-IN4-IP",
    #                      "MIO-AES-OUT4-IP", "MIO-AES-IP", "MIO-AVR", "MIO-AVT",
    #                      "MIO-CCE-3G", "MIO-DANTE", "MIO-DM4-LB4", "MIO-DM-TRK-SA",
    #                      "MIO-GE-RJ45-IP", "MIO-HDMI-2-4K-IP", "MIO-HDMI-IN-3G",
    #                      "MIO-HDMI-IN1-4K-IP", "MIO-HDMI-OUT-3G",
    #                      "MIO-HDMI-OUT1-4K-IP", "MIO-IT-IP",
    #                      "MIO-USB-A", "MIO-USB-B"):
    #     print(f"DEBUG: Validated as Default module:{module_name}, slot:{module_slot}")
    #     device = ScorpionModule(frame, module_name, module_slot, module_name)
    else:
        print("I am a default scorpion module."
              f"module:{module_name}, slot:{module_slot} ")
        device = ScorpionModule(frame, module_name, module_slot, module_name)
    return device

# Find function
def find(dev_info_obj):
# def find(snmp={}, http={}, nbt={}, group=None):
    '''Locate and return the appropriate model for the given parameters.

    If 'group' is specified, will search for a model by group.

    Otherwise:
    The 'snmp' dictionary should have the SNMPv2 system OID values:
        sysDescr - The 'most used' descriptor by Evertz products.
        sysName - A few Evertz products use this instead (bug).
        sysObjectID - In rare instances if sysName/sysDescr not defined.
        sysLocation - In rare instances used to determine node type.
    The 'http' dictionary could contain the following:
        cfgWeb - Dictionary of reserved varids and their values
        cfgJSON - Dictionary of reserved varids and their values
        status - The text of the status line (eg. "200 OK HTTP/1.1")
        headers - Dictionary of the server reply headers.
        content - The body of the reply. May be `None`.
    The 'nbt' dictionary

    Must be fast! Should return `None` if no model found.
    '''
    start = time.time()
    # Get the card name from the device.
    device_results = dev_info_obj.results
    # Get the sysDescr from the device.
    # sysDescr = dev_info_obj.snmp.get(asnmp.sysDescr)
    sysDescr = dev_info_obj.snmp.get('1.3.6.1.2.1.1.1.0', '')
    card_name = device_results.get('card_name', '')

    # Search for match -------------------------------------------------
    if (sysDescr in ('IPG570X19', 'IPG5703G18SFP', 'IPG570X1925G') or
            card_name.startswith('570IPG')):
        print("Debug: Creating IPG570 Object")
        # cfgProduct = ('570IPG-X19', '570IPG-X19-10G', '570IPG-3G18-SFPP12')
        return models.ipg570.IPG570(dev_info_obj)
    # elif ('670IPG' in sysDescr or '670IPG' in cfgProduct):
    #     return ipg670.IPG670
    # elif ('MMA10G' in sysDescr or 'MMA10G' in cfgProduct):
    #     return None#return mma10g.MMA10G # Too complex for this release
    # elif ('EXE-VSR' in sysDescr or 'EXE-VSR' in cfgProduct or
    #       'EXE-NCS' in cfgProduct or cfgProduct == '3080IPX-128'):
    #     # Detected 'EXE-VSR'. SNMP='EXE-VSR', cfgWeb = 'EXE-NCS' or 'EXE-VSR'.
    #     return exe.EXE
    # elif '5601MSC' in sysDescr:
    #     return msc5601.MSC5601
    # elif '5700MSC' in sysDescr:
    #     return msc5700ip.MSC5700IP
    # elif (('VIP' in sysDescr and '3067' in sysDescr) or
    #       ('VIP' in cfgProduct and '3067' in cfgProduct)):
    #     # Detected 3067VIP10G (sysDescr='VIP10GHW3067')
    #     return vip10g.VIP10G
    # elif sysDescr == "magnum" and httpContent:
    #     # Detected MagnumSDVN
    #     #print("Found MagnumSDVN")
    #     return magnumsdvn.MAGNUMSDVN
    # elif (('570' in sysDescr and 'ITXE' in sysDescr) or
    #       ('570' in cfgProduct and 'ITXE' in cfgProduct)):
    #     # Detected a 570ITXE - cfgJSON only.
    #     return itxe570.ITXE570
    # elif ('BLADE' in sysDescr or cfgProduct.startswith('EVBLADE')): # or
    #        #('blade' in sysDescr or cfgProduct.startswith('evblade'))):
    #     # evBlade - SW no response, Pnodes cfgJSON only.
    #     return bladez.BLADEZ
    elif ('3606FC' in card_name or '3606FC' in sysDescr
        or 'SCORPION-2' == card_name or 'SCORPION2'.lower() == sysDescr.lower()
        or 'SCORPION-4' == card_name or 'SCORPION4'.lower() == sysDescr.lower()
        or 'SCORPION-6' == card_name or 'SCORPION6'.lower() == sysDescr.lower()
        or 'SCORPION-X18' == card_name or 'SCORPIONx18'.lower() == sysDescr.lower()
        or 'SCORPION-SX18' == card_name or 'scorpions18'.lower() == sysDescr.lower()):
        # print("DEBUG: I am a Scorption! I should populate the model now.")
        frame = Scorpion(dev_info_obj)
        # Create the individual modules based on the probe.
        module_list = []
        for slot, module in enumerate(frame.modules):
            # Create scorpion module object
            # print(f"frame: {frame.name}, slot: {slot}, module: {module}")
            if module == "None" or module is None or module == '':
                continue
            scorp_module = create_scorpion_module(frame, module, slot)
            if scorp_module:
                module_list.append(scorp_module)
        # return scorpion.SCORPION(snmp,http,nbt)
        frame.modules = module_list
        return frame
    else:
        # Nothing was found.
        return None