# SCAN.PY

import time                 # Python timing
import struct               # Binary data packing/unpacking.
import socket               # IP Address handling.
import threading            # Multiple threads
import traceback            # Generate error messages.
import collections          # Used for namedtuple and deque.
# Third-party imports -------------------------------------------------
# Local imports -------------------------------------------------------
import ahttp                        # Evertz asynchronous HTTP operations.
import asnmp                        # Evertz asynchronous SNMP operations.
if not asnmp.AES or not asnmp.DES:
    raise ImportError("Requires pycryptodomex for SNMP v3 support")
import anbt                         # Evertz asynchronous NetBIOS library.
from snmpdata import ENTERPRISES    # { enterprise_num: (name, weblink) }
import models.__info__ as models


class InterfaceInfo(object):
    """Class to hold information about an interface on a device.

    self.if_num = The interface number assigned by its OperatingSystem.
    self.MAC = MAC address in colon-separated lower-case hex format.
    self.name = The interface name (possibly blank)
    self.IP = The assigned IP (possibly blank)
    """
    def __init__(self, if_num: int, mac_octets: str, name: str = ""):
        """Immediately parse the mac_str into colon-separated format."""
        self.if_num = if_num
        if not mac_octets or len(mac_octets) != 6:
            raise ValueError("Invalid MAC address string")
        if not isinstance(mac_octets, (bytes, bytearray)):
            mac_octets = mac_octets.encode('l1', errors="ignore")
        mac_bytes = struct.unpack('6B', mac_octets)
        self.MAC = ":".join("%02x" % octet for octet in mac_bytes)
        self.name = name
        self.IP = ""

    def __repr__(self) -> str:
        """InterfaceInfo(if_num=2, mac="00:02:c5:12:33:f3", name="eth0")"""
        return "%s(if_num=%s, mac=%s, name=%s)" % (
            self.__class__.__name__, self.if_num, self.MAC, self.name)
#end class InterfaceInfo(object)


class DeviceInfo(object):
    """Container class to hold info on discovered devices.

    self.IP = String IP address of device.
    self.name = Discovered name of the device.
    self.icon = Name of icon to use in Tree View.
    self.ok = True if device was contacted, False otherwise.
    self.model = Model object containing model found.
    self.current_version = Software 'major'.'minor'.'build'
    self.selected = If the device is selected
    self.GROUP = The group the device belongs to
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

    Additionally we try to get interface information. This is obtained
    via SNMP IF-MIB (if supported) or SNMPv3 EngineID (if reported).
      self.interfaces = { MAC: (interface_name, IP_address) }
    Note it could be { MAC: (None, None) } if no information was
    extracted for a specific MAC address.
    """
    # Reserved VarIDs.
    VARIDS = ('1@s',    # Product Name (e.g. "570IPG-X19")
              '2@s',    # Creation Date (e.g. "20180207")
              '3@i',    # Revision Major (e.g. "1")
              '4@i',    # Revision Minor (e.g. "0")
              '6@s',    # Build Number (e.g. "0452-App F")
              '8@s',    # Serial Number (e.g. "7678130045")
              '9@s',    # Name PRODUCT (e.g. "570IPG")
              '10@s',   # Revision BRDREV (e.g. "A")
              '11@i',)  # Build Number BRDBLD (e.g. "2")
    # SNMP v2 management OIDs to fetch.
    OIDS = (asnmp.sysDescr, asnmp.sysName, asnmp.sysObjectID, asnmp.sysLocation)
    # SNMP v2 Evertz common MIB OIDs to fetch.
    MINICARD_VALUES = ('cardName', 'boardSerialNumber', 'softwareRevisionMajor',
                       'softwareRevisionMinor', 'softwarePointReleaseNumber',
                       'boardName', 'boardRevision', 'hardwareBuildNumber')
    MINICARD = {name: asnmp.MINICARD[name] for name in MINICARD_VALUES}
    # POLL_TIMEOUT = 20   # Timeout for a device to poll
    POLL_TIMEOUT = 15   # Timeout for a device to poll
    SNMP_RETRIES = 1    # Default number of retries for SNMP operations.
    SNMP_TIMEOUT = 2.0  # Default timeout per retry of SNMP operations.
    MAX_SNMP = 1        # Maximum number of simultaneous SNMP operations.

    def __init__(self, IP, snmp_thread, http_thread, nbt_thread):
        # Convert IP address to 32-bit representation.
        try:
            self.IP32 = struct.unpack("!L", socket.inet_aton(IP))[0]
        except (socket.error, struct.error):
            raise ValueError("Invalid address %s" % repr(IP))
        # Convert IP back to string representation.
        self.IP = '.'.join(str((self.IP32 >> i) & 0xFF) for i in (24, 16, 8, 0))
        self.GROUP = ''               # The device group it belongs to
        self.icon = "unknown"           # Case-sensitive
        self.ok = False                 # True if refresh succeeded.
        self.http_thread: ahttp.HttpThread = http_thread
        self.snmp_thread: asnmp.SnmpThread = snmp_thread
        self.nbt_thread: anbt.NbtThread = nbt_thread
        self.model = None
        self.https = False          # Start with regular HTTP.
        self.started = False        # False, or timestamp of when probe started.
        self.selected = False       # If device is selected for upgrade/license
        self.elapsed = 0            # Time in seconds probe has taken.
        self.percent = 0            # Percentage probe is done.
        self.http = {}              # HTTP results from probe.
        self.snmp = {}              # SNMP results from probe.
        self.cfgweb = False
        self.cfgjson = False
        self.results = {}           # Specific information from probe.
        self.interfaces = {}        # { MAC: (interface_name, ip_address) }
        self.requests = {}          # Ongoing operations.
        self.profile = {}
        self.nbt = []               # NetBIOS results from probe
        self.TIMEOUT = ((self.SNMP_RETRIES + 1) * self.SNMP_TIMEOUT) + 0.5
        self.current_firmware = ""  # Software Version 'major.minor.build'

    def http_get(self, path, params=None, headers={}, safe=',',
                 allow_redirects=False, max_redirects=2, queue=None,
                 callback=None, timeout=4.0, https=None):
        """Accessor method for non-blocking HTTP or HTTPS gets.

        Equivalent to calling:
        self.http_thread.get('http://%s%s' % (self.IP,path), block=False)

        Will use 'http' if https is False, or 'https' if https is True.
        If https is not specified, uses self.https to determine schema.
        By default allow_redirects is False so won't follow redirects.
        Returns the non-blocking operation object.
        """
        if https is None:
            https = self.https
        schema = 'http' if https is False else 'https'
        return self.http_thread.get("%s://%s%s" % (schema, self.IP, path),
                                    params=params, headers=headers, block=False,
                                    safe=safe, allow_redirects=allow_redirects,
                                    max_redirects=max_redirects, queue=queue,
                                    callback=callback, timeout=timeout)

    def snmp_get(self, requests, community='public', op_retries=None,
                 op_timeout=None, timeout=4.0, queue=None, callback=None):
        """Delegator method for non-blocking SNMP multiple gets.

        Equivalent to calling:
        self.snmp_thread.batchGet(self.IP, requests, block=False)

        'requests' should be a list of operations. Each operation can
        contain one or more OIDs (up to 1024). The maximum number of
        simultaneous pending SNMP operations is set by self.MAX_SNMP.
        The default number of retries and timeout per attempt are set by
        self.SNMP_RETRIES and self.SNMP_TIMEOUT, if not specified.
        """
        if op_retries is None:
            op_retries = self.SNMP_RETRIES
        if op_timeout is None:
            op_timeout = self.SNMP_TIMEOUT
        return self.snmp_thread.batchGet(self.IP, requests, community=community,
                                         op_retries=op_retries, timeout=timeout,
                                         op_timeout=op_timeout, queue=queue,
                                         callback=callback, block=False,
                                         max_pending=self.MAX_SNMP)

    def snmp_walk(self, base_oid, queue=None, max_results=None,
                  community='public', version=0, bulk=False, max_repetitions=1,
                  timeout=10.0, op_retries=1, op_timeout=2.0, callback=None):
        '''Delegator method for non-blocking SNMP walks.

        Equivalent to calling:
        self.snmp_thread.walk(self.IP, base_oid, block=False)

        Will perform repeated GetNext or GetBulk (bulk=True) operations
        on the agent until either:
            1. the returned OIDs no longer branch from the 'base_oid'.
            2. 'max_results' (if specified) is returned.
            3. The timeout elapses.
        By default 'max_results' is None to disable that check.

        The results of the walk are added to the queue as 2-tuples of
        (branch_oid, value) where 'branch_oid' is a tuple containing the
        last OID value numbers, not including the 'base_oid' portion.
        If a queue is not specified, one is created.

        Returns a WalkOperation() object.
        '''
        return self.snmp_thread.walk(
            self.IP, base_oid, queue=queue, max_results=max_results,
            community=community, version=version, bulk=bulk,
            max_repetitions=max_repetitions, timeout=timeout, block=False,
            op_retries=op_retries, op_timeout=op_timeout, callback=callback)

    def get_cfgweb(self, parameters, path='/cgi-bin/cfgweb', timeout=4.0,
                   https=None, queue=None, callback=None):
        '''Delegator for non-blocking http_thread.get_cfgweb(self.IP).

        If https is not specified, will use self.https.
        Always non-blocking (block=False)
        '''
        if https is None:
            https = self.https
        return self.http_thread.get_cfgweb(
            self.IP, parameters, path=path, timeout=timeout, https=https,
            queue=queue, callback=callback, block=False)

    def get_cfgjson(self, parameters, path='/cgi-bin/cfgjsonrpc',
                    version='2.0', jsonId=None, https=None, queue=None,
                    callback=None, timeout=4.0):
        '''Delegator for self.http_thread.get_cfgjson(self.IP)

        If https is not specified, will use self.https.
        Always non-blocking (block=False)
        The operation.result will contain { varId: value }.
        '''
        if https is None:
            https = self.https
        return self.http_thread.get_cfgjson(
            self.IP, parameters, path=path, version=version, jsonId=jsonId,
            https=https, queue=queue, callback=callback, timeout=timeout,
            block=False)

    def probe(self):
        """Initiate a probe of this device for SNMP/HTTP/NBT probes."""
        # Don't do anything if already refreshing (start timestamp set).
        if self.started:
            return
        self.started = time.time()
        self.percent = 0
        self.ok = False
        self.http.clear()
        self.snmp.clear()
        self.interfaces.clear()
        self.nbt = []

        # Start the http operation to get WebEASY version.
        self.requests['httpOp'] = self.http_get(
            '/version.txt', allow_redirects=True, timeout=4.5)
        # Start the first SNMP operation.
        self.requests['snmpOp'] = self.snmp_thread.get(
            self.IP, asnmp.sysDescr, version=0, timeout=self.SNMP_TIMEOUT,
            retries=self.SNMP_RETRIES, block=False)
        # TODO Start first SNMPv3 operation
        self.requests['snmpv3Op'] = self.snmp_thread.get(
            self.IP, asnmp.sysObjectID, version=3, userName='evertz', block=False)
        # Start NetBIOS query to device.
        if self.nbt_thread and self.nbt_thread.is_alive() is True:
            self.requests['nbtOp'] = self.nbt_thread.query(self.IP, block=False)

    def poll(self):
        """Check ongoing SNMP/HTTP/NBT operations for results.

        Returns percent complete."""
        # Return 100% if no active poll ongoing (maybe we finished already).
        if not self.started:
            return 100
        # Process ongoing operations and grab results.
        snmpOp = self.process_snmp(self.requests.pop('snmpOp', None))
        snmpv3Op = self.process_snmpv3(self.requests.pop('snmpv3Op', None))
        nbtOp = self.process_nbt(self.requests.pop('nbtOp', None))
        httpOp = self.process_http(self.requests.pop('httpOp', None))
        # Push back into self.requests dictionary (if new operations created).
        self.requests['snmpOp'] = snmpOp
        self.requests['snmpv3Op'] = snmpv3Op
        self.requests['nbtOp'] = nbtOp
        self.requests['httpOp'] = httpOp
        # Search for a model if SNMP and HTTP operations are complete.
        model = None
        # if httpOp is None and snmpOp is None:
        #     self.model = models.find(self)
        #     if model:
        #         self.poll_finished(model=model)
        #         return 100
        # Check for poll timeout.
        self.elapsed = abs(time.time() - self.started)
        if self.elapsed > self.POLL_TIMEOUT:
            # We took too long. Force everything to stop.
            print("Device %s timed out %ssec." % (self.IP, self.POLL_TIMEOUT))
            print(f"Device {self.IP} timed out after {self.POLL_TIMEOUT} seconds.")
            self.poll_finished(model=None)
            self.percent = 100

        # print(f"Polling {self.IP}, percent complete: {self.percent}%")
        # Check if all operations are finished.
        if not any((snmpOp, snmpv3Op, nbtOp, httpOp)):
            self.poll_finished(model)
            self.percent = 100
        return self.percent

    def process_http(self, httpOp: ahttp.HttpOperation):
        """Process current http operation (might be None).

        Returns the operation if not complete yet or None if finished.
        Will return a new HTTP operation on successful response.
        """
        # Is the http request complete?
        if httpOp and httpOp.finished is True:
            # print(f"Processing HTTP response for {self.IP}, URL: {httpOp.req_url}, Status: {httpOp.status_code}")

            self.profile.setdefault(httpOp.url, []).append(abs(time.time() - httpOp.started))
            URL = httpOp.req_url.lower()
            if URL.endswith('version.txt'):     # WebEASY version -----
                webVer = None
                if httpOp.ok is True:
                    # Device is running WebEASY. Extract version.
                    content = httpOp.content.decode('utf8', errors='replace')
                    for line in content.splitlines():
                        if line.startswith('V') and line[1:4].isdigit() is True:
                            webVer = "v.%c.%c" % (line[1], line[2])
                    # Set self.https to True if we got redirected to https.
                    if httpOp.url.lower().startswith('https'):
                        self.https = True
                if webVer:
                    # Put into self.http results.
                    self.http['version'] = webVer
                    # Start cfgWeb/cfgJSON requests
                    version = float(webVer[2:])
##                    print("%s %.1fs - Got webEasy version %r, https=%s" %
##                          (self.IP, elapsed, version, self.https))
                    if version < 1.5:
                        # WebEASY v1.4 or older mostly uses cfgWeb API.
                        httpOp = self.get_cfgweb(self.VARIDS)
                        self.cfgweb = True
                    else:
                        # WebEASY v1.5 supports cfgJSON API and maybe alias.
                        httpOp = self.get_cfgjson(self.VARIDS + ('9150@s',))
                        self.cfgjson = True
                    if httpOp.ok is True:
                        params = {varid: value
                                  for varid, value in httpOp.result.items()
                                  if varid and value}
                        # Populate self.results
                        self.extract_results(params)
                else:
                    # No webeasy. Try to fetch default URL.
                    httpOp = self.http_get(
                        '/', allow_redirects=True, timeout=self.TIMEOUT)
            elif URL.endswith('/'):     # Generic HTTP -----------------
                # Record results of HTTP operation (if any) and end probe.
                #  print("%s %.1fs - Generic HTTP: ok=%s, error=%s, status=%s" %
                #        (self.IP, elapsed, httpOp.ok, httpOp.error, httpOp.status))
                if httpOp.content:
                    self.http['status'] = httpOp.status_code    # e.g. 200
                    self.http['headers'] = httpOp.headers       # {name: value}
                    self.http['content'] = httpOp.content       # Raw bytes
                self.percent += 25
                httpOp = None
            elif URL.endswith('cfgjsonrpc'):    # cfgJSON --------------
                # Extract cfgJSON parameters, if any.
                params = {}
                # print("%s %.1fs - cfgJSON complete, ok=%s, error=%s, %d params" %
                #       (self.IP, elapsed, httpOp.ok, httpOp.error, len(httpOp.result)))
                if httpOp.ok is True:
                    params = {varid: value
                              for varid, value in httpOp.result.items()
                              if varid and value is not None or value != ""}
                self.http.setdefault('cfg_json', {}).update(params)
                # self.results=['']
                # Populate self.results
                self.extract_results(params)
                if not params and 'cfg_web' not in self.http:
                    # cfgJSON failed. Try cfgWeb probe.
                    # print("%s cfgJSON failed, attempting cfgWeb" % self.IP)
                    httpOp = self.get_cfgweb(self.VARIDS)
                else:
                    # We got our cfgJSON so we're done!
                    self.percent += 25
                    httpOp = None
            elif URL.endswith('cfgweb'):    # cfgWeb -------------------
                # Extract cfgWeb parameters, if any.
                params = {}
                if httpOp.ok is True:
                    params = {varid: value
                              for varid, value in httpOp.result.items()
                              if varid and value}
##                    print("%s %.1fs - cfgWeb complete, %d params" %
##                          (self.IP, elapsed, 0 if not params else len(params)))
                self.http.setdefault('cfg_web', {}).update(params)
                # Populate self.results
                self.extract_results(params)
                if not params and 'cfg_json' not in self.http:
                    # cfgWeb failed. Try cfgJSON probe.
                    #print("%s CfgWeb failed. Starting cfgJSON" % self.IP)
                    httpOp = self.get_cfgjson(self.VARIDS)
                elif params and '9150@s' not in params:
                    # cfgWeb alias hack - Request separately in case it fails.
                    #print("%s requesting cfgWeb alias" % self.IP)
                    httpOp = self.get_cfgweb(('9150@s',))
                else:
                    # We got our cfgWeb parameters so we're done!
                    self.percent += 25
                    httpOp = None
            else:
                print("*** Unknown request URL: %r" % URL)
                self.percent += 25
                httpOp = None
        return httpOp

    def process_snmp(self, snmpOp):
        """Process current SNMP operation (might be None).

        Returns either the same operation (if not finished) or None if
        SNMP probe is completed, or a new operation if continuing.
        """
        IF_PHYS_MIB = "1.3.6.1.2.1.2.2.1.6"     # ifPhysAddress table
        IF_DESC_MIB = "1.3.6.1.2.1.2.2.1.2"     # ifDescr table
        LLDP_MIB = "1.0.8802.1.1.2.1.3.7.1"     # lldpLocPortEntry table.
        if snmpOp and snmpOp.finished is True:

            self.profile.setdefault(snmpOp.__class__.__name__, []).append(abs(time.time() - snmpOp.started))
            if isinstance(snmpOp, asnmp.SNMPOperation):
                # debug
                if self.IP == '172.16.199.10':
                    print(f"{self.IP}: snmp: {snmpOp.error}, oid: {snmpOp.oids}")
                if snmpOp.oids:
                    # Got a response for sysDescr, device running an SNMP agent.
                    self.snmp.update(snmpOp.oids)
                    # Schedule GET for next critial OID.
                    missing = [oid for oid in self.OIDS if oid not in self.snmp]
                    if missing:
                        # Get the next OID in self.OIDS.
                        snmpOp = self.snmp_thread.get(
                            self.IP, missing[0], version=0,
                            timeout=self.SNMP_TIMEOUT,
                            retries=self.SNMP_RETRIES, block=False)
                    else:
                        # All critial OIDs probed. Process sysObjectID.
                        self.extract_results(self.snmp)
                        # Try to get Evetz MINICARD.
                        snmpOp = self.snmp_thread.batchGet(
                            self.IP, [[OID] for OID in self.MINICARD.values()],
                            op_retries=self.SNMP_RETRIES, timeout=self.TIMEOUT,
                            op_timeout=self.SNMP_TIMEOUT, max_pending=1,
                            block=False)
                else:
                    # No response for a critical OID. Stop all SNMP operations.
                    # print("DEBUG: No OIDS found. IP:%s ok: %s, error: %s" % (self.IP, snmpOp.ok, snmpOp.error))
                    self.percent += 25
                    snmpOp = None
            if isinstance(snmpOp, asnmp.GetBatchOperation):
                # Batch get result for Evertz MINICARD OIDs.
                if snmpOp.oids:
                    # Process the SNMP MINICARD OIDs into self.results.
                    self.extract_results(self.snmp)
                # All SNMP OIDs have been probed. Try walking IF-MIB.
                snmpOp = self.snmp_walk(IF_PHYS_MIB, bulk=True)
            elif isinstance(snmpOp, asnmp.WalkOperation):
                # Reply to a walk operation. Was it successful?
                if snmpOp.ok is True and snmpOp.queue.qsize():
                    # We got results! Process them into self.interfaces.
                    results = [snmpOp.queue.get() for _ in range(snmpOp.queue.qsize())]
                    # results = [(tuple(oids), value), ...]
                    if snmpOp.base_oid == IF_PHYS_MIB:
                        # Got a walk reply to get Physical Addresses
                        results = {suffix[0]: value for suffix, value in results
                                   if len(suffix) == 1 and value}
                        for if_num, octets in results.items():
                            try:
                                interface_info = InterfaceInfo(if_num, octets)
                            except ValueError:
                                pass
                            else:
                                self.interfaces[if_num] = interface_info
                        # Got phyical, send walk for IF_DESC_MIB
                        snmpOp = self.snmp_walk(IF_DESC_MIB, bulk=True)
                    elif snmpOp.base_oid == IF_DESC_MIB:
                        # Got a walk reply to interface names.
                        results = {suffix[0]: value for suffix, value in results
                                   if len(suffix) == 1 and value}
                        for if_num, if_name in results.items():
                            if if_num in self.interfaces:
                                self.interfaces[if_num].name = if_name
                                # Add eth 0 mac address to the results
                                if if_name == 'eth0':
                                    self.results['mac'] = self.interfaces.get(if_num).MAC
                        # Done! The IF-MIB gave us everything, no need for LLDP.
                        self.percent += 25
                        snmpOp = None
                    elif snmpOp.base_oid == LLDP_MIB:
                        # Got a walk reply for LLDP-MIB. Parse the results.
                        lldp = {}   # { port_num: {table_oid: value} }
                        for suffix, value in results:
                            if len(suffix) == 2:
                                # suffix = (table_oid, port_num)
                                table_oid, port_num = suffix
                                lldp_data = lldp.setdefault(port_num, {})
                                lldp_data[table_oid] = value
                        # Scan through lldp dictionary and record MAC addresses.
                        for port_num, lldp_data in lldp.items():
                            subtype = lldp_data.get(2)      # .2 = PortIdSubtype
                            if subtype == 3:    # macAddress (3)
                                octets = lldp_data.get(3)   # .3 = PortId
                                name = lldp_data.get(4)     # .4 = Description
                                try:
                                    self.interfaces[port_num] = InterfaceInfo(
                                        port_num, octets, name=name)
                                    self.results['mac'] = self.interfaces[port_num].MAC
                                except ValueError:
                                    pass
                        # All done, no more requests to make.
                        self.percent += 25
                        snmpOp = None
                else:
                    # No response to SNMP walk.
                    if snmpOp.base_oid == IF_PHYS_MIB:
                        # IF-MIB not try LLDP-MIB.
                        snmpOp = self.snmp_walk(LLDP_MIB, bulk=True)
                    else:
                        # Walks failed. Stop SNMP probe.
                        self.percent += 25
                        snmpOp = None
        return snmpOp

    def process_snmpv3(self, snmpv3Op):
        """ Process current SNMPv3 operation (might be None).

        Returns either the same operation (if not finished) or None if
        SNMP probe is completed, or a new operation if continuing.

        """
        # If device supports snmpv3 look at the engine ID and flag that snmpv3 is supported.
        if snmpv3Op and snmpv3Op.finished is True:
            self.profile.setdefault('SNMPv3', []).append(abs(time.time() - snmpv3Op.started))
            # print(f"DEBUG: EngineID:{snmpv3Op.engineId}")
            if snmpv3Op.engineId and len(snmpv3Op.engineId) >= 5:
                # Extract enterprise ID from engineID:
                enterprise_num = struct.unpack('!L', snmpv3Op.engineId[:4])[0] & 0x7fffffff
                self.results['enterprise'] = enterprise_num
                vendor, website = ENTERPRISES.get(enterprise_num, (None, None))
                self.results['vendor'] = vendor
                if snmpv3Op.engineId[4] == b'\x03':
                    # Score! engineId contains a MAC address!
                    mac_bytes = snmpv3Op.engineId[5:11]
                    if len(mac_bytes) == 6:
                        self.interfaces[0] = InterfaceInfo(0, mac_bytes)
                        print("Got %s SNMPv3 enterprise %s (%s), MAC: %s" % (self.IP, enterprise_num, vendor, self.interfaces[0].MAC))
                        # set the mac address if its not set already
                        if not self.results.get('mac'):
                            self.results['mac'] = self.interfaces[0].MAC
            # Stop SNMPv3 probe.
            self.percent += 25
            snmpv3Op = None
        return snmpv3Op

    def process_nbt(self, nbtOp: anbt.NbtOperation):
        """Process current NetBIOS operation (might be None).

        Returns either the same operation (if not finished) or None if
        NetBIOS query is finished.
        """
        # Check up on NetBIOS query.
        if nbtOp and nbtOp.finished is True:
            self.profile.setdefault('NBT', []).append(abs(time.time() - nbtOp.started))
            # nbtOp.reply.names is a list of 2-tuples of (name, flags).
            if nbtOp.ok is True and nbtOp.reply:
                # Sort names so lower value of flags is at start of list.
                names = sorted(nbtOp.reply.names, key=lambda n: n[1])
                # Filter names to only workstation IDs (ends with \x00).
                names = [name[:15].strip() for name, flags in names
                         if name.endswith('\x00')]
                if names:
                    self.results['netbios'] = names[0]
            # Stop NBT probe.
            self.percent += 25
            nbtOp = None
        return nbtOp

    def poll_finished(self, model=None):
        """Stop the poll and set the model (if found)."""
        self.started = False
        self.requests.clear()
        #
        # print("%s finished in %.1f sec." % (self.IP, self.elapsed))
        # print("DEBUG:poll_finished, IP:%s, results:%s, snmp: %s, http %s" % (self.IP, self.results, self.snmp, self.http))
        # print("%s finished results %.1s sec." % (self.IP, self.results))
        # if self.elapsed > 10:
        #     for name, times in self.profile.items():
        #         print("\t%s times: %s" % (name, ', '.join("%.1f" % t for t in times)))

        # Set the http_name in self.results if we got an HTTP response.
        if self.http.get('version'):
            # It's running WebEASY
            self.results['http_name'] = str(self.http['version'])
        elif self.http:
            # Try to get the HTML <title> element, otherwise Server header.
            http_name = self.http.get('headers', {}).get('Server', '')
            body = self.http.get('content', b'')
            title = body[body.find(b'<title>'):body.find(b'</title>')][7:]
            http_name = title if len(title) > len(http_name) else http_name
            if hasattr(http_name, 'decode'):
                http_name = http_name.decode('utf8', 'ignore')
            self.results['http_name'] = http_name
        else:
            # The HTTP title is not found
            http_name = None

        # Pick the best interface from self.interfaces, if we have any.
        sorted_interfaces = sorted(self.interfaces.items())
        if sorted_interfaces:
            self.results['interface'] = sorted_interfaces[0][1]
        # Get the model
        self.model = models.find(self)
        # Assign our icon.
        if self.model:
            self.icon = 'evertz'    # Known and modelled device
        elif self.results.get('enterprise', None) == 6827:  # Evertz
            self.icon = 'evertz'   # Evertz Microsystems Ltd.
        elif self.results.get('enterprise', None) == 8072:     # Net-SNMP
            self.icon = 'linux'     # Net-SNMP (server-based product).
        elif self.results.get('vendor', None):
            self.icon = 'gear'      # Other registered SNMP vendor.
        elif self.results.get('netbios'):
            self.icon = 'pc'        # Likely a PC, server or workstation.
        elif self.http:
            self.icon = 'web'       # Web-reply only.
        else:
            self.icon = 'unknown'
        if self.model or self.results:
            self.ok = True
            print(f"Finished scanning {self.IP}, Results: {self.results}")

        #     print("DEBUG:Poll_finished I AM OKAY! %s, ip:%s, resp:%s " % (self.ok, self.IP, self.results))
        # else:
        #     print("DEBUG:Poll_finished DeviceInfo object is not set to ok... %s, ip:%s, resp:%s " % (self.ok, self.IP, self.results))

    def extract_results(self, params: dict):
        """Translate parameters from VarIDs to self.results dictionary.

            params: { VarID: value } or { OID: value }

            'card_name': str,       # From cardName OID or WebEASY 1@s.
            'serial': str,          # From boardSerialNumber OID or WebEasy 8@s.
            'major': int,           # FW version softwareRevisionMajor OID or WebEasy 3@i.
            'minor': int,           # FW version softwareRevisionMinor OID or WebEASY 4@i.
            'build': int,           # FW version softwarePointReleaseNumber or WebEASY 6@s.
            'board_name': str,      # boardName OID or WebEASY 9@s.
            'board_rev': str,       # boardRevision OID or Webeasy 10@s
            'board_build': int,     # boardbuild OID or Webeasy 11@i
            'alias': str,           # Card alias from WebEASY 9150@s.
        """
        # print("DEBUG:extract_results, IP:%s, params: %s, results:%s, snmp: %s, http %s" % (self.IP, params, self.results, self.snmp, self.http))
        # Process sysObjectID to results['enterprise'] and ['vendor'].
        sysObjectID = params.get(asnmp.sysObjectID)
        if sysObjectID and isinstance(sysObjectID, str):
            # Split ObjectID into enterprises component.
            if sysObjectID.startswith('1.3.6.1.4.1.'):
                oid, dot, rest = sysObjectID[12:].partition('.')
                if oid.isdigit() is True:
                    vendor, weblink = ENTERPRISES.get(int(oid), (None, None))
                    self.results['enterprise'] = int(oid)
                    if vendor:
                        self.results['vendor'] = vendor
        # 'card_name' is either SNMP OID or WebEASY VarID '1@s'.
        card_name = params.get('1@s', params.get(self.MINICARD['cardName']))
        if card_name:
            self.results['card_name'] = card_name
        serial = params.get('8@s', params.get(self.MINICARD['boardSerialNumber']))
        if serial:
            self.results['serial'] = str(serial)
        major = params.get('3@i', params.get(self.MINICARD['softwareRevisionMajor']))
        if major is not None and major != "":
            try:
                self.results['major'] = int(major)
            except (TypeError, ValueError):
                pass
        minor = params.get('4@i', params.get(self.MINICARD['softwareRevisionMinor']))
        if minor is not None and minor != "":
            try:
                self.results['minor'] = int(minor)
            except (TypeError, ValueError):
                pass
        build = params.get('6@s', params.get(self.MINICARD['softwarePointReleaseNumber']))
        if build:
            self.results['build'] = str(build)
        board_name = params.get('9@s', params.get(self.MINICARD['boardName']))
        if board_name:
            self.results['board_name'] = str(board_name)
        board_rev = params.get('10@s', params.get(self.MINICARD['boardRevision']))
        if board_rev:
            self.results['board_rev'] = str(board_rev)
        board_build = params.get('11@i', params.get(self.MINICARD['hardwareBuildNumber']))
        if board_build is not None and board_build != "":
            try:
                self.results['board_build'] = int(board_build)
            except (TypeError, ValueError):
                pass
        alias = params.get('9150@s')
        if alias:
            self.results['alias'] = str(alias)
        # Setup the firmware version
        self.current_firmware = '%s.%s.%s' % (self.results.get('major', ''),
                                              self.results.get('minor', ''),
                                              self.results.get('build', ''))
#end class DeviceInfo(object)


class ScanThread(threading.Thread):
    """A Thread to perform device discovery on a list of IPs"""
    def __init__(self, baseIP: int, count: int, name="Scan Thread", **kwargs):
        # Initialize Thread.
        super(ScanThread, self).__init__(name=name, **kwargs)
        self.startIP = baseIP & 0xffffffff
        self.endIP = (self.startIP + count) & 0xffffffff
        # Create new HTTP, SNMP, and NBT threads for this scan.
        self.http_thread = ahttp.start()
        self.snmp_thread = asnmp.start()
        self.nbt_thread = anbt.start()
        self.polling = []
        self.discovered = collections.deque()
        self.end_event = threading.Event()
        self.percent = 0
        self.status = "Initializing"

    def run(self):
        """This is the method that is run in a separate thread."""
        # 1) Create DeviceInfo object for each IP address to poll.
        # for IP32 in range(16, 18 + 1):
        for IP32 in range(self.startIP, self.endIP + 1):
            IP = socket.inet_ntoa(struct.pack("!L", IP32))
            # print(f"Probing device at {IP}")
            deviceinfo = DeviceInfo(IP, snmp_thread=self.snmp_thread,
                                    http_thread=self.http_thread,
                                    nbt_thread=self.nbt_thread)
            deviceinfo.probe()
            self.polling.append(deviceinfo)
        # 2) Poll each device and add to self.discovered when complete.
        try:
            self.scan()
        except Exception as err:
            traceback.print_exc()
            self.status = "Exception %s" % str(err)
        else:
            self.status = "Aborted" if self.polling else "Finished"
        # 3) Stop all threads.
        self.http_thread.stop(block=False)
        self.snmp_thread.stop(block=False)
        self.nbt_thread.stop(block=False)

    def scan(self):
        """Scan all DeviceInfo objects in self.polling."""
        print("Scanning %s to %s (%s total)" % (self.polling[0].IP, self.polling[-1].IP, len(self.polling)))
        total_poll = len(self.polling)
        while self.polling and not self.end_event.is_set():
            self.status = "Scanning %s IPs" % len(self.polling)
            lowest_percent = 100
            for deviceinfo in tuple(self.polling):
                # Poll the device and update lowest_percent.
                percent = deviceinfo.poll()
                lowest_percent = min(percent, lowest_percent)
                if percent >= 100:
                    # Remove from self.device and add to self.discovered.
                    self.polling.remove(deviceinfo)
                    if deviceinfo.ok is True:
                        self.discovered.append(deviceinfo)
                    # else:
                    #     print("DEBUG:SCAN DeviceInfo object is not set to ok... %s, ip:%s, resp:%s " % (deviceinfo.ok, deviceinfo.IP, deviceinfo.results))
            # self.percent = lowest_percent
            self.percent = round((total_poll - len(self.polling)) * 100 / total_poll)
            time.sleep(0.010)
        print(f"Scanning completed. Discovered {len(self.discovered)} devices. -------------------------------------------------")


    def stop(self, block=True):
        """Stop the thread, optionally blocking until fully stopped."""
        self.end_event.set()
        if block is True:
            self.join()
#end class ScanThread(threading.Thread)


# if __name__ == '__main__':
#     # Small app to scan a subnet
#     # Good lab subnets to scan: 172.17.141.0, 172.17.235.0, 172.17.223.0
#     import argparse

#     parser = argparse.ArgumentParser(
#         description="Perform a scan on all devices in a subnet",
#         epilog="Report bugs to jessiec@evertz.com")
#     parser.add_argument('172.17.141.0', type=argparse.FileType('r', encoding='utf8'),
#                         help="File containing text to give model")
#     parser.add_argument('172.17.235.0', type=argparse.FileType('r', encoding='utf8'),
#                         help="Optional second file to give to the model after "
#                         "first file")
#     # Initialize a ScanThread, run it, and then display results

if __name__ == '__main__':
    import argparse

    print("Starting network scan...")

    parser = argparse.ArgumentParser(
        description="Perform a scan on all devices in a subnet",
        epilog="Report bugs to jessiec@evertz.com"
    )

    # Use a variable name instead of a hardcoded IP
    parser.add_argument('subnet', help="Subnet to scan (e.g., 172.17.141.0)")
    args = parser.parse_args()

    # Convert subnet to base IP (assuming /24 subnet)
    try:
        base_ip = struct.unpack("!L", socket.inet_aton(args.subnet))[0]
    except socket.error:
        print("Error: Invalid subnet format. Please use an IP like 172.17.141.0")
        exit(1)

    num_ips = 255  # Assuming /24, adjust if necessary

    scan_thread = ScanThread(base_ip, num_ips)
    scan_thread.start()
    scan_thread.join()  # Ensure it completes before script exits

    print("Scanning complete. Devices discovered:")
    for device in scan_thread.discovered:
        print(f"Device: {device.IP}, MAC: {device.results.get('mac', 'Unknown')}, Model: {device.model}")


## python3 scan.py 172.17.141.0
