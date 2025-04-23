#=======================================================================
# anbt.py - Asynchronous NetBIOS over IP/UDP (NBT) protocol module
#
# Contains very basic functions to send a UDP NBSTAT name query packet
# to port 137 and parse the Name Query Response packet. This is the
# same thing as running the command:
#   C:\nbtstat
# Requires asnmp.py module.
#
# RFC1001 (NetBIOS Concepts)
# RFC1002 (NetBIOS Detail)
#
# Evertz Microsystems DVG - 2014
# Tested with Python 2.7.1 and Python 3.3.4 ============================
"""Asyncrhonous NetBIOS over IP/UDP (NBT) query thread.

Requires the asnmp.py module for UdpOperation and UdpThread.

Performs basic NBSTAT name query to UDP port 137 and parses the Name
Query Response packet. This is the same thing as running the command:
    nbtstat -A [IP]

EXAMPLE USAGE:
>>> import anbt
>>> nbt = anbt.start()
>>> op = nbt.query("192.168.50.140")
>>> op.finished
True
>>> op.ok
True
>>> op.reply.names
[('STARFRUIT     \x00', 17408), ('WORKGROUP      \x00', 50176), ('STARFRUIT      ', 17408)]
>>>
"""
import time         # Timing functions.
import struct       # Unpacking binary packet data.
# import socket       # Sockets.
# import random       # For generating sequence numbers.
# import threading    # Python threading and Thread class.
try:
    import Queue                # Synchronized Queue
except ImportError:
    import queue as Queue       # Python3 compatibility.
from asnmp import ID_POOL, ID_LOCK, get_id, release_id, STR, BYTES
from asnmp import UdpOperation, UdpThread

VERSION = 0.1       # Initial version
VERSION = 0.2       # Python3 support
VERSION = 0.3       # PEP8 fixes, better documentation, block=True by default.
# ----------------------------------------------------------------------
class NbtPacket(object):
    """Class to encode and decode NetBIOS Node Status Packets.

    self.datagram = The encoded NBT packet as a 'bytes' object.
    """
    # NetBIOS OperationCodes and ResultCodes.
    OPCODES = {0: "Query", 5: "Registration", 6: "Release", 7: "WACK",
               8: "Refresh"}
    RESULT_CODES = {0: "", 1: "Format Error", 2: "Server Failure",
                    4: "Unsupported Request Error", 5: "Refused Error",
                    6: "Name Active Error", 7: "Name in Conflict Error"}
    # NetBIOS names for Microsoft are 15 characters followed by a suffix.
    COMPUTERNAME_SUFFIX = {
        0x00: "Workstation Service", 0x01: "Messenger Service",
        0x03: "Messenger Service", 0x06: "RAS Server Service",
        0x1F: "NetDDE Service", 0x20: "File Server Service",
        0x21: "RAS Client Service", 0x22: "Microsoft Exchange Interchange",
        0x23: "Microsoft Exchange Store", 0x24: "Microsoft Exchange Directory",
        0x30: "Modem Sharing Server", 0x31: "Modem Sharing Client",
        0x43: "SMS Clients RemoteCtrl", 0x44: "SMS Administrators RemoteCtrl",
        0x45: "SMS Clients Remote Chat", 0x46: "SMS Clients Remote Transfer",
        0x4C: "DEC Pathworks TCP/IP on NT", 0x42: "McAfee Anti-Virus",
        0x52: "DEC Pathworks TCP/IP NT", 0x87: "Microsoft Exchange MTA",
        0x6A: "Microsoft Exchange IMC", 0xBE: "Network Monitor Agent",
        0xBF: "Network Monitor App", 0x2B: "Lotus Notes Server Service", }
    USERNAME_SUFFIX = {0x03: "Messenger Service", }
    DOMAIN_SUFFIX = {0x00: "Domain Name",
                     0x1B: "Domain Master Browser",
                     0x1C: "Domain Controllers",
                     0x1D: "Master Browser",
                     0x1E: "Browser Service Elections", }

    def __init__(self, transaction_id=None, opcode=0, nm_flags=0,
                 questions=[('*', 0x0021, 0x0001)], datagram=None):
        if datagram:
            self.decode(datagram)
        else:
            self.transaction_id = None
            self.opcode = int(opcode)
            self.nm_flags = int(nm_flags)
            self.r = 0
            self.result_code = 0
            self.error = ""
            self.questions = questions
            self.rr_name = ""
            self.names = []
            self.statistics = []
            self.encode()

    def get_datagram(self):
        """Required by UdpThread. Return the raw datagram of the packet."""
        return self.datagram

    def get_id(self):
        """Required by UdpThread. Returns the transaction id of the packet."""
        return self.transaction_id

    def clear_id(self):
        """Clears the transaction ID of the packet."""
        if self.transaction_id:
            release_id(self.transaction_id)
            self.transaction_id = None

    def get_error(self):
        """Required by UdpOperation. Return the message's error status."""
        return self.error

    def encode(self):
        """Encode packet to self.datagram with a new transaction id."""
        # Release current transaction_id (if exists) and set a new one.
        self.clear_id()
        self.transaction_id = get_id(maxval=0xFFFF)
        # Generate header
        packed = (self.r & 0x01) << 15
        packed += (self.opcode & 0x0F) << 11
        packed += (self.nm_flags & 0x7F) << 4
        packed += (self.result_code & 0x0F)
        header = struct.pack('!HHHHHH', self.transaction_id, packed,
                             len(self.questions), 0, 0, 0)
        data = []
        for qname, qtype, qclass in self.questions:
            # HACK: Should be level-2 encoding here. Append 0x00 to fake it.
            name = self.encode_L1(qname) + b'\x00'
            data.append(struct.pack("!%dsHH" % len(name), name, qtype, qclass))
        self.datagram = header + b''.join(data)

    @staticmethod
    def encode_L1(name):
        """Return NetBIOS first level encoding of name - RFC1001 (pg26).

        The given name will be padded to 16 bytes and the resultant
        33-byte encoding (length + 32 bytes) is returned as 'bytes'.
        """
        name = BYTES(name)
        if len(name) != 16:
            name = name.ljust(16, b'\x00')
        encoded = bytearray(((byte >> shift) & 0x0F) + 0x41
                            for byte in bytearray(name) for shift in (4, 0))
        # Add in length byte and return.
        encoded.insert(0, len(encoded))
        return bytes(encoded)

    def decode(self, datagram):
        """Decode raw NetBIOS packet bytes into object. Must be fast.

        Can only decode Query replies with NBSTAT resource records.
        Will raise ValueError on an invalid packet."""
        try:
            header = struct.unpack_from("!HHHHHH", datagram)
        except struct.error:
            raise ValueError("Bad NetBIOS packet header")
        self.transaction_id, flags, qdcount, ancount, nscount, arcount = header
        # Make sure we have a Query reply with no questions
        self.r = flags >> 15
        if self.r != 1:
            raise ValueError("Got NetBIOS request, expected reply")
        if qdcount != 0:
            raise ValueError("NetBIOS reply has %d questions" % qdcount)
        self.opcode = (flags >> 11) & 0x0F
        if self.opcode != 0:
            raise ValueError("NetBIOS opcode %d not supported" % self.opcode)
        self.nm_flags = (flags >> 4) & 0x7F
        self.result_code = flags & 0x0F
        self.error = self.RESULT_CODES.get(self.result_code, "Unknown Error")
        self.rr_name = ''
        self.names = []
        self.statistics = []
        if not self.error:
            # Decode Resource Record Section (rr_name, names, statistics)
            pos = 12
            # Decode rr_name and update pos. Will raise ValueError on failure.
            labels, pos = self.decode_name(datagram, pos)
            self.rr_name = '.'.join(labels)
            # Decode resource record fields.
            try:
                rr_fields = struct.unpack_from("!HHLHB", datagram, pos)
            except struct.error:
                raise ValueError("Bad NetBIOS resource record section")
            rr_type, rr_class, ttl, rdlength, num_names = rr_fields
            pos += 11
            # Accept only NBSTAT types (0x0021) in Internet (1) class.
            if rr_type != 0x0021:
                raise ValueError("Bad resource record type 0x%04x" % rr_type)
            if rr_class != 1:
                raise ValueError("Bad resource record class 0x%04x" % rr_class)
            if ttl != 0:
                raise ValueError("Bad resource record TTL %d" % ttl)
            # Decode Node Status Response names (up to num_names).
            while pos + 18 < len(datagram) and len(self.names) < num_names:
                name, flags = struct.unpack_from("!16sH", datagram, pos)
                self.names.append((STR(name, 'latin_1'), flags))
                pos += 18
            # Decode statistics (if present, ignore truncation).
            try:
                self.statistics = struct.unpack_from("!6sBBHHHHHHLLHHHHHHHHH",
                                                     datagram, pos)
            except struct.error:
                pass

    @staticmethod
    def decode_name(packet, pos):
        """Decode NetBIOS name as specified in RFC1001 (page 25).

        Must be passed the entire original 'packet' so that pointers can
        be resolved. Returns a tuple of (labels, pos) where 'labels' is
        a list of decoded label strings that comprise the name and 'pos'
        is the position decoding stopped, right after a null terminator.

        Will raise ValueError if decoding fails.
        """
        labels = []
        while True:
            ## Decode label at current position and update to new position.
            ## Allow ValueError to be raised on a decoding error.
            label, pos = NbtPacket.decode_L2(packet, pos)
            # A zero-length string (null terminator) indicates end of name.
            if not label:
                break
            # Got a label. Append and continue loop.
            labels.append(label)
        # Return tuple of decoded labels and finishing position.
        return (labels, pos)


    @staticmethod
    def decode_L1(data):
        """Decode first level encoding as specified in RFC1001 (pg26).

        Decodes the 'data' bytes of 32 characters and returns the
        result as 'bytes'. If the passed 'data' is not 32 bytes long,
        it is returned unmodified.
        """
        # Only decode NetBIOS 32-byte strings.
        if len(data) != 32:
            return data
        # Reverse encoding on each character pair (c1,c2).
        name = bytearray((((c1 - 0x41) & 0x0F) << 4) + (((c2 - 0x41) & 0x0F))
                         for c1, c2 in zip(*(iter(bytearray(data)),) * 2))
        # Return original string as 'bytes' (null terminators removed).
        return bytes(name.partition(b'\x00')[0])

    @staticmethod
    def decode_L2(packet, pos):
        """Decode second level encoding as specified in RFC883 (page 31).

        Must pass the entire original 'packet' so that we can resolve
        pointers used for compression. The 'pos' is the byte position to
        start decoding at. Any 32-character names are passed through the
        first level decoding to resolve the NetBIOS encoding scheme.

        Will raise ValueError on an invalid pointer or truncated name.
        Returns 2-tuple of (name, pos) with decoded string 'name' and
        new position 'pos'.
        """
        # Fail if the position is out of bounds in the packet.
        if pos < 0 or pos >= len(packet):
            raise ValueError("Position %d is out of packet" % pos)
        # Get and check length code.
        length = struct.unpack_from('B', packet, pos)[0]
        #print("length=%d" % length)
        if length == 0:
            # Zero-length string (null terminator) signals end of list.
            return ("", pos + 1)
        elif length & 0xC0 == 0:
            # Normal length (high two bits clear). Try level-1 decoding.
            name = NbtPacket.decode_L1(packet[pos + 1:pos + 1 + length])
            if not name:
                raise ValueError("Name at position %d length %d truncated" %
                                 (pos, length))
            else:
                # Got a valid name. Return it.
                return (STR(name, 'latin_1'), pos + 1 + length)
        elif length & 0xC0 == 0xC0:
            # Upper two bits are set. Indicates compression pointer.
            print("length=0x%02x, length & 0xC0=0x%02x" % (length, length & 0xc0))
            if pos + 1 >= len(packet):
                raise ValueError("Pointer value truncated at %d" % pos)
            # Read next 8-bits of pointer.
            next_byte = struct.unpack_from('B', packet, pos + 1)[0]
            pointer = ((length & 0x3F) << 8) + (next_byte & 0xFF)
            ## Make sure pointer points inside packet and make sure it
            ## points BACKWARDS to protect against infinite recursion.
            if pointer < 0 or pointer >= pos:
                raise ValueError("Invalid pointer %d at position %d" %
                                 (pointer, pos))
            # Recursively decode pointer.
            name, unused = NbtPacket.decode_L2(packet, pointer)
            # Return decompressed name and new position just past pointer.
            return (name, pos + 2)
        else:
            raise ValueError("Invalid length code 0x%02x at position %d" %
                             (length, pos))
#end class NbtPacket(object)



class NbtOperation(UdpOperation):
    """Class to manage a single NetBIOS name query and node status response."""
    def __init__(self, host, retries=1, timeout=2.0, queue=None,
                 callback=None, max_pending=1):
        # Generate the request packet.
        self.request = NbtPacket()
        # Call UDP Operation base class constructor with port 137.
        UdpOperation.__init__(self, host, 137, retries=retries,
                              timeout=timeout, queue=queue, callback=callback,
                              max_pending=max_pending)
#end class NbtOperation(UdpOperation)


class NbtThread(UdpThread):
    # Override packet UdpThread uses when decoding received datagram.
    Packet = NbtPacket

    def query(self, host, retries=1, timeout=2.0, queue=None,
              callback=None, block=True):
        """Schedule a NetBIOS name query for the given host."""
        if not self.is_alive():
            raise RuntimeError("Cannot perform query - Thread not running")
        if block is True:
            queue = Queue.Queue()
            callback = None
        # Instantiate an Operation for this message.
        operation = NbtOperation(host, retries=retries, timeout=timeout,
                                 queue=queue, callback=callback)
        # Queue up operation to be sent and return it.
        self.queue.put(operation)
        if block is True:
            try:
                queue.get(block=True, timeout=timeout * (retries + 1) + 1.0)
            except Queue.Empty:
                pass
        return operation
#end class NbtThread(UdpThread)


def start(**kwargs):
    """Return a new, started and running NbtThread instance."""
    thread = NbtThread(**kwargs)
    thread.start()
    return thread


# Simple console-based net scanner if run as a program.
if __name__ == "__main__":
    import sys              # Python system
    import socket           # socket.inet_aton
    import argparse         # GNU-style argument parsing
    import anbt

    # Create and configure argument parser.
    description = ("Perform mass NetBIOS queries on an entire subnet.")
    epilog = "Report bugs to cbeytas@evertz.com"
    parser = argparse.ArgumentParser(description=description, epilog=epilog)
    parser.add_argument('IP', metavar="SUBNET",
                        help="IP Address of subnet to scan.")
    parser.add_argument('-v', '--verbose', action='store_true', dest='debug',
                        default=0, help="Increased verbosity (debug output)")
    parser.add_argument('-t', '--throttle', type=int, dest='throttle',
                        default=1000, help="Maximum packets/sec to transmit")
    # Parse arguments into args object.
    args = parser.parse_args()
    try:
        subnet = struct.unpack("!L", socket.inet_aton(args.IP))[0] & 0xFFFFFF00
    except (socket.error, struct.error):
        print("Invalid subnet IP '%s'" % args.IP)
        sys.exit(1)

    subnetIP = ".".join(str((subnet >> i) & 0xFF) for i in (24, 16, 8, 0))
    print("Scanning subnet %s..." % subnetIP)

    # Create and start NetBIOS Thread
    thread = NbtThread(debug=int(args.debug), throttle=args.throttle)
    thread.start()

    # Schedule queries to be deposited into a queue.
    queue = Queue.Queue()
    ops = []
    for num in range(1, 255):
        host = ".".join(str(((subnet + num) >> i) & 0xFF) for i in (24, 16, 8, 0))
        op = thread.query(host, queue=queue, block=False)
        ops.append(op)

    # Wait for thread to go idle ---------------------------------------
    t0 = time.time()
    while thread.is_alive() is True and not all(op.finished for op in ops):
        print('%s, %-40s%s' % ('Idle' if thread.idle else 'Busy',
                               thread.status, '\b' * 72))
        time.sleep(1.0)
    elapsed = abs(time.time() - t0)
    print('%s, %-40s - Took %.3fs' % ('Idle' if thread.idle else 'Busy',
                                      thread.status, elapsed))
    # Retrieve all successful replies from queue.
    print("Queue length=%d" % queue.qsize())
    replies = []
    while not queue.empty():
        replies.append(queue.get())
    print("%d replies" % len(replies))
    ok = [operation for operation in replies if operation.ok is True]
    print("%d OK" % len(ok))
    results = []
    for operation in ok:
        print(operation.reply.names)
        #results.append((operation.agent, oids.get(sysDescr)))
    # for host, descr in sorted(results):
    #     print("%s\t%-40s" % (host, descr[:40]))

    # Stop thread and exit
    thread.stop(block=True)
    print("End of line")
    sys.exit(0)

# Test packets/names used for unit testing -----------------------------
NAME_QUERY_PACKET = (
    b"\xc8\x20\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20"
    b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")
NAME_RESPONSE_PACKET = (
    b"\xc8\x20\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00"  # Header - 12 bytes
    b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"  # rr_name (L2 encoded)
    b"\x00\x21"          # rr_type = 0x0021 (NBSTAT)
    b"\x00\x01"          # rr_class = 0x0001 (Internet class)
    b"\x00\x00\x00\x00"  # TTL = 0
    b"\x00\x77"          # RDLENGTH = 119 bytes
    # Resource Data Section - 73 bytes
    b"\x04"              # NUM_NAMES = 4
    b"DARRENMNOTE\x20\x20\x20\x20\x00" b"\x04\x00"    # NODE_NAME + NODE_FLAGS
    b"DARRENMNOTE\x20\x20\x20\x20\x20" b"\x04\x00"    # NODE_NAME + NODE_FLAGS
    b"EVERTZ_MICROSYS\x00" b"\x84\x00"                # NODE_NAME + NODE_FLAGS
    b"EVERTZ_MICROSYS\x1e" b"\x84\x00"                # NODE_NAME + NODE_FLAGS
    # Statistics - 46 bytes
    b"\x64\x31\x50\x94\x21\x61"  # Unique Unit ID (48bits)
    b"\x00\x00"                  # JUMPERS, TEST_RESULT
    b"\x00\x00\x00\x00"          # VERSION_NUMBER, PERIOD_OF_STATISTICS
    b"\x00\x00\x00\x00"          # NUMBER_OF_CRCs, NUMBER_ALIGNMENT_ERRORS
    b"\x00\x00\x00\x00"          # NUMBER_OF_COLLISIONS, NUMBER_SEND_ABORTS
    b"\x00\x00\x00\x00"          # NUMBER_GOOD_SENDS
    b"\x00\x00\x00\x00"          # NUMBER_GOOD_RECEIVES
    b"\x00\x00\x00\x00"          # NUMBER_RETRANSMITS, NUMBER_NO_RESOURCE_CNDTNS
    b"\x00\x00\x00\x00"          # NUMBER_FREE_CMD_BLKS, TOTAL_NUM_COMMAND_BLKS
    b"\x00\x00\x00\x00"          # MAX_TOTAL_NUM_CMD_BLKS, NUM_PENDING_SESSIONS
    b"\x00\x00\x00\x00"          # MAX_NUM_PEND_SESSIONS, MAX_TOTAL_SESSIONS
    b"\x00\x00"                  # SESSION_DATA_PACKET_SIZE
    # Extra data at end of packet?
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
# Test from RFC 1002 page 6. Resolves to ["FRED          ","NETBIOS","COM"]
NAME_RESPONSE_PACKET2 = (
    b"\xc8\x20\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    b"\x20EGFCEFEECACACACACACACACACACACACA\x07NETBIOS\x03COM\x00"
    b"\x00\x21\x00\x01\x00\x00\x00\x00\x00"
    b"\x77\x04DARRENMNOTE\x20\x20\x20\x20\x00\x04\x00DARRENMNOTE\x20\x20\x20"
    b"\x20\x20\x04\x00EVERTZ_MICROSYS\x00\x84\x00EVERTZ_MICROSYS\x1e\x84\x00"
    b"\x64\x31\x50\x94\x21\x61\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
## Test compatible with RFC 883 page 33. NbtPacket.decode_name(TEST_NAME2, 20)
## pos0=(["translate", "bing", "com"], 20), pos20=(["F", "ISI", "ARPA"], 32),
## pos32=ValueError(Invalid pointer 37 at position 37), (circular pointer)
## pos40=(["FOO", "F", "ISI", "ARPA"], 51),
## pos51=ValueError(Invalid length code), pos52=ValueError(Pointer Truncated).
TEST_NAME2 = (b"\x09translate\x04bing\x03com\x00"
              b"\x01F\x03ISI\x04ARPA\x00"
              b"\x04live\xC0\x25\x00"
              b"\x03FOO\xC0\x14\xC0\x16\xC0\x1a\x00"
              b"\x80\x00\xc0")
