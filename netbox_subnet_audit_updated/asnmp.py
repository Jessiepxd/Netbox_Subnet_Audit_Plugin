"""Asynchronous SNMP v1/v2c/v3 thread speed optimized for mass polling.

Based off asn1tools package: https://github.com/eerimoq/asn1tools
    pip install asn1tools

Does not use pysnmp due to inherit slowness of that library.
No support for directly loading MIBs. All parameters
are addressed by OID. Can walk the OID tree and fetch many instance
values for a set of OIDs automatically. Also has support to query the
entire LLDP database of a device in one operation.
For SNMPv3 only User Security Model is supported. No TSM support yet.

EXAMPLE USAGE:
>>> import asnmp
>>> snmp = asnmp.SnmpThread()
>>> snmp.start()
>>> op = snmp.get("172.17.141.231", asnmp.sysDescr)
>>> op.finished
True
>>> op.ok
True
>>> op.oids
{'1.3.6.1.2.1.1.1.0': 'EXE-NCS'}
>>>
"""
import sys                      # Python system.
import time                     # Python timing.
import zlib                     # For compressed SNMP spec.
import errno                    # Standard C library error codes.
import struct                   # Packing binary data into bytes.
import socket                   # Python socket module.
import random                   # Random number generation
import base64                   # For packed SNMP spec.
import binascii                 # Only really needed for Python2.
import threading                # Python multithreading module.
import traceback                # Exception traceback
import collections              # NamedTuple
# Supported hashing algorithms.
from hashlib import md5, sha1, sha224, sha256, sha384, sha512
try:
    import Queue                # Synchronized Queue
except ImportError:
    import queue as Queue       # Python3 compatibility.
try:
    import asn1tools            # https://github.com/eerimoq/asn1tools
except ImportError:
    print("** ASN1 Tools import failed. Please install with:")
    print("\tpython -m pip install asn1tools")
    raise
# pip install pycryptodomex
try:
    from Cryptodome.Cipher import DES   # SNMPv3 RFC3414 privacy algorithm.
    from Cryptodome.Cipher import AES   # RFC3826 privacy algorithm.
    # https://tools.ietf.org/html/draft-reeder-snmpv3-usm-3desede-00
    from Cryptodome.Cipher import DES3
except ImportError:
    DES = AES = DES3 = None

# Module Defines -------------------------------------------------------
VERSION = 0.1       # Initial version - July 10, 2018
VERSION = 0.2       # Clean version - August 21, 2018
VERSION = 0.3       # Removed string->IPAddress conv. (snmp.IpAddress(value))
VERSION = 0.4       # Deferred SnmpMessage encoding to get_datagram() method.
VERSION = 0.5       # Fixed GetMany timeout (op_timeout, op_retries).
VERSION = 0.6       # Strip NULLs at end of OctetString (for 2430RX2-10G b0045)
VERSION = 0.7       # Added check to snmp_set for varBinds parameter.
VERSION = 0.8       # Ditched pySNMP and pyAsn1 in favor of asn1tools
                    # asn1tools encodes ~4x faster and decodes 7x faster.
VERSION = 0.9       # Updated GetMany for queue usage and speed. Added instGet.
VERSION = 1.0       # Rename BulkGetOperation to GetManyOperation.
                    # Added SNMPv2c support and GetBulk method.
                    # Added WalkOperation.
VERSION = 1.1       # Fixed bug with SNMP sets
VERSION = 1.2       # Added cancel method to GetMany/GetInst/Walk operations.
VERSION = 1.3       # Reduced max_oids to 55.
VERSION = 1.4       # Trim pending dictionary when host_pending is empty.
VERSION = 1.5       # Helpful message on failed asn1tools import.
VERSION = 1.6       # Catch ENETRESET exception for TTL expired packets.
VERSION = 1.7       # Python3 support, added 'encoding' for strings.
VERSION = 1.8       # Added MINICARD v4 definition, better exception handling.
VERSION = 1.9       # First version with SNMP v3 support.
VERSION = 2.0       # Consolidated SNMPOperation class.
VERSION = 2.1       # Added start convenience function.
VERSION = 2.2       # Fixed MINICARD def and renamed bulkGet to batchGet.
VERSION = 2.3       # Fixed snmp set pduType. Removed 'warnings' from operation
VERSION = 2.4       # Changed default SNMP version back to v1.
VERSION = 2.5       # Added 'failed' dictionary for SNMP v2/v3 error handling.
VERSION = 2.6       # Added 'requestOids' to SNMPOperation for convenience.
VERSION = 2.7       # Remove all __iter__ checks, call get_engine_info only if
                    # present. Rename GetManyOperation to GetBatchOperation.
                    # Differentiate self.started, self.timestamp timestamps.

# Define SNMP v2 management OIDs --------------------------------------
# iso(1).org(3).dod(6).internet(.1).mgmt(2).mib-2(1).system(1)
sysDescr = "1.3.6.1.2.1.1.1.0"      # A textual description of the entity.
sysObjectID = "1.3.6.1.2.1.1.2.0"   # The base OID of the entity
sysUpTime = "1.3.6.1.2.1.1.3.0"     # The uptime in 1/100ths of a second.
sysContact = "1.3.6.1.2.1.1.4.0"    # Textual contact information.
sysName = "1.3.6.1.2.1.1.5.0"       # Administratively assigned name.
sysLocation = "1.3.6.1.2.1.1.6.0"   # Physical location of this node.

# Constants required by SNMPv3
USM = 3                 # User-based security model (RFC 3414)
USM_TIME_WINDOW = 150   # Time window is 150 seconds (RFC 3414 2.2.3)
IPAD = bytes(bytearray(i ^ 0x36 for i in range(256)))   # HMAC Inner padding
OPAD = bytes(bytearray(o ^ 0x5c for o in range(256)))   # HMAC Outer padding
UsmSecurity = collections.namedtuple(
    'UsmSecurity', ('engineId', 'engineBoots', 'engineTime', 'userName',
                    'hmac', 'salt'))
DEFAULT_USM_SECURITY = UsmSecurity(engineId=b'', engineBoots=0, engineTime=0,
                                   userName=b'', hmac=b'', salt=b'')
UsmCredentials = collections.namedtuple(
    'UsmCredentials', ('privKey', 'authKey', 'hashFunc', 'cipher'))
EngineInfo = collections.namedtuple(
    'EngineInfo', ('engineId', 'engineBoots', 'engineTime', 'timestamp'))
REPORT_FLAG = 0x04  # Requests that a response be sent (mandatory for GETs).
PRIV_FLAG = 0x02    # Message is/will be encrypted.
AUTH_FLAG = 0x01    # Message is/will be authenticated.

# Python 2/3 compatibility definitions ---------------------------------
if sys.version_info[0] == 2:
    # Python2 BYTES convert unicode to str, otherwise pass (str,bytes,bytearray)
    BYTES = lambda text, encoding='utf8': (
        text.encode(encoding, 'replace') if isinstance(text, unicode) else text)
    # Python2 STR convert unicode to str. For str/bytes/bytearray encode to
    # unicode then to str to remove invalid characters.
    STR = lambda data, encoding='utf8': (
        data.encode(encoding, 'replace') if isinstance(data, unicode) else
        data.decode(encoding, 'replace').encode(encoding, 'replace'))
    NUMBER_TYPES = (int, float, long)
    TEXT_TYPES = (unicode,)
else:
    # Python3 BYTES convert str to bytes, otherwise pass (bytes, bytearray).
    BYTES = lambda text, encoding='utf8': (
        bytes(text, encoding, 'replace') if isinstance(text, str) else text)
    # Python3 STR pass if already str, otherwise convert to string.
    STR = lambda data, encoding='utf8': (
        data if isinstance(data, str) else str(data, encoding, 'replace'))
    NUMBER_TYPES = (int, float)
    TEXT_TYPES = (str,)

# Define miniCard MIB OIDs ---------------------------------------------
MINICARD_BASE = "1.3.6.1.4.1.6827.50.24."
MINICARD = {
    # SOFTWARE SECTION (.2)
    'cardName': MINICARD_BASE + "2.1.0",                # String
    'creationDate': MINICARD_BASE + "2.2.0",            # String
    'softwareRevisionMajor': MINICARD_BASE + "2.3.0",   # Integer
    'softwareRevisionMinor': MINICARD_BASE + "2.4.0",   # Integer
    'softwarePointReleaseNumber': MINICARD_BASE + "2.5.0",  # Integer
    'softwareBuildNumber': MINICARD_BASE + "2.6.0",     # String
    'softwareOptions': MINICARD_BASE + "2.7.0",         # String
    # HARDWARE SECTION (.2)
    'firmwareLocation': MINICARD_BASE + "3.1.0",        # String
    'boardSerialNumber': MINICARD_BASE + "3.2.0",       # String
    'boardName': MINICARD_BASE + "3.3.0",               # String
    'boardRevision': MINICARD_BASE + "3.4.0",           # String
    'hardwareBuildNumber': MINICARD_BASE + "3.5.0",     # Integer
    # LOGGING SERVICES TABLE (.4)
    # 'logStreamIndex': MINICARD_BASE + '4.1.1.1.%s',     # Integer (enum)
    # 'logStreamEnable': MINICARD_BASE + '4.1.1.1.%s',    # 1=disabled, 2=enabled
    # 'logStreamIP': MINICARD_BASE + '4.1.1.1.%s',        # String
    # 'logStreamPort': MINICARD_BASE + '4.1.1.1.%s',      # Integer
    # 'logStreamPhyIface': MINICARD_BASE + '4.1.1.1.%s',  # Integer
    # 'logStreamLevel': MINICARD_BASE + '4.1.1.1.%s',     # Integer (enum)
}

# SNMPv1/v2c/v3 protocol description in ASN.1 notation.
# Zipped, base-64 encoded RFC1155/RFC1157/RFC3412 is compiled at runtime.
# data = base64.encodebytes(zlib.compress(open("SNMPv123.asn1", 'rb').read()))
SNMP_SPEC = """
eJytWktz4kgSvvMrKvpiiECEBfg1E3vwA7vZsLHXYM/0dvhQSGWstVBpSwWYnej/Ppn1kEog2XR7
FT4IKSsrn19mpex5ZPISZQT++EIQmiW+5DzOyOl41PFJlrIgeo4CKiOekGcuyHh0c0fmLMvojGWd
hueRodzLCCUBn0+jRBPyZ3J/ee77Bwdtc3Okb0729ZNe3+/amz4y+YORGVcbzHkmkVkKrKZRHMk1
oUlIsmiexlGAPyUn2SJNuZCExrGWaMlEBjuDRGZjb3wzJBeDy+FoOBnejsbkt9/+Qc4GV8NRozH4
8+72fjImsO/gcXD/bfJ1OLpqEHNFiWQiYbJNwkiwQHKxbpP5bC7bOQl7S5mI5iyRNG6TVERLKlmb
MFwJvzKWFbSwye3ZPwfnE2/y7W7QJhN+wfOXt9P/wA4jOofV+n68BqZvbTJGfZn5ldOfpmgEZWRL
OGJyxcXraRgK8EqbDFN7m6865wuUrE2u6GIGO01A9EkUvAL1bUr/u2C/Nxoop3xhBMz+ghbGe8G5
bOT2MBIrXcjwYjCaDC+Hg3tl2L8ggDjhYtbstUjIw+Zhi/jkR6Mw4fuL7RZqDdqa5NeHa7q4xvXI
Dmt6uMb4bdd9+mqfwsXvrLGcUR1l2ZA9R0lkc4MrTxO5ToGLYHO+ZCFphiwFW8GysNVomMhJIDKy
YgnkaaI8czM8a5TjR+28JU/OKFPR8iEnHVSK1/nX2+H5gPyVR5HKQFY4piZEaRGi3ioKWUXMurkB
warskhXosuxt5P+z4HMECwJocdjJVy+SsYYnsJ66Rg/X122ydcEuoKxgUkRsCeEhGIR8JrOcUcLH
i+BFW0A9+L7/RIY3d9fD8+HE4QqM9t+O9yHYApYqZyq+WQris84Gu2GSSZoEaLDv/jvs/I/YsSS8
fb6Jpo8RW2npuhvsiMOu+x67HzoeXMdV+zpZzKdM4N1wNBlcDe4Ln2VgxmSmQuZ8MpiQ8eQe0LN4
z3MzbkWjA6DzVK5zn7mybUVLtYBUY5xmUUbAnCbQsKfuLQTmL2cIheZew2L+SiI0mvsCKoutxTSS
gipI0/BZCmgOWSW2s0AlexsKLGYdlDTB3EUKH1jYJqsIKtqUoX4Q1cCpIJtGM8+qZNQ57Jv1lyZD
ugdHx6414VW1JI1tw1UbukD/vLBsbPBFkUBCQVh8AXrI47naThHkqxT776d3GLenWJKJm2RuLJHm
ePjvAWn2W62G4zvFgJRZuIllIpU09zudfvekf3J41D050CyUhw2DDRbdHVnkkbCtSG9HFuiNPHh0
gwV4BPFDvoR8MY2ZtxLgLhZ+0ZCsgstKXdqxX2M6u804YfQV878IFIwljaQIsstuKVwKsi3lDmuU
84/7/cOjfn//qHe0f3Jw4B/6oOZgdNEwLdiRp9C8ugczct7wUOM3dBxREsQLiE/b29l6sOwGeQXA
BlJDGcikerj6Dqq+MXJ8eXl/e0OclvH3RsmEa7KiquEMWcBBNrf7tT0n5Kx84QsQeBHHa02JCBlJ
LemNJn801GiD8eBfD4MR5pnlQXKkLRJL8tSL2ZLFdkeX3QYfF0wMT89XJpTY3oOGbTIFGe27rkGY
KCkKzbYsDt/NK9+kud9qf0jVbfqtSqIfJeyEsj9fJFjysfEpIsBXRwATDA6+W+qaUoTASiUFH0IP
JaIZHE/QQ6ejb05wEboARE6kwUhtphWDLjbZkzYYCyMphvq6u3goeojCbangkgc81qQooKZC8mqM
nTHpmabEPLli8l4/8GBZu0SZsDeHHChH8KCSGoTRrHUPoOwgGJpWJZxq6NZkz77fQ8CwRgF7J2wF
qNs0adfqbMhrmBby6gdlEbIt1cY1qgEqpuXYmMCTLYUmLww2faHBq4reEkpsOQsFnS7i15K5zuBB
pQS6dLniDtWTSuIsmaePXc+RWkvhbUstmMIz57pXT5Bqo5bmIVUOAI3KUC/VlcOxXb8dA3oBVMdK
YtdVmrL7VM15vC0G+d6rIbaaa5b9J1fjnBiJkEbr+xUicsoYnIqmGY+Z1D7VgVcc6Y3YG47T2xy4
OiKFlWbLd5r+8KlSz7LvNOlRjZ6F9zTd8VOFnkisqOf0zZtGCZaELMdVXNf1+0f9495h/6hh8aEO
1E1IelHo7LTZmDMhuPDg0CEX2QbROzhur4QPcP27aG4vyflZNANI/5hUn4WwPDe7O5BPafiIHVGz
twOxYDS8TeI1NIofE89YAgo2D3aS+TQIoMo2D1ubp0nsCwzYcNj5Q1YrwZPZBBru5tEmr19idc2S
mXxpHpeZ/RKrQaL7lOaJy+yXWGmX+fufkyrh5+BRrMFN3/8cK2glATiiTEJdN8J1W/mh+6dYQZ3j
CxGwh4QuaRRT6NKbfk8x+1lW2K9E8hK4sLDp9z9j9kUScsvo4HO2wvYHmqP/KctrDPBN4P+8B+Uf
IpLaRuWA/4wHFXr4x61fYPVjEx4BiNlb/noLQ5dURCh+gdiEPFJxBr+uQZiNam3FsDMs9dzUoE9B
eQItM3QNkA1QA+uIsLAgkTTzs/+DQrdxaBvuvBS+VJbozTaxk3cA7+iOZxrAQmcECqjMBMXJger/
2tAvwgFwnemT3PACt4IS78zC7Pi1sN47YyY8cJvpQ9WexUgHnkkPSQu2dVMl1VQDhyjQLStq5DSc
6o3bFv5EDYZDQziWVMidqvCKirmm3qUQx1HyesFXyU5lGIkf0p2KcPn0hJi0EGynisxm6YhFs5cp
F9ccqu0upbnwvxn9BlCkd0UAHIObVQRP8/jlBg4TiSRwyE5I9Fx2HxybAdAqtizOAOaB6+6tDMSg
j+Awy2KaZpA8U4grTCccvscUzhlNwVrq4wCNDQpjsOLrRIcgimA/g+FjG8AFIe7vjC/nDNvAuXOc
qhhjfji5w+vn4MNSE0utXhj6OlBQJ31S+hTmyjjcOA7oiRk6h9qDNM5fyJ7zNWDPnuHhuM9XekRO
p3zJFHI5w29n9qG4lj+D1GhnbQFZYizgWKSs5e2lfZcPxvDLpxqMLXvvj8YMjR333AmOPSnui3Fw
EWUplcEL/C7Pw9SUwZlq6SmcGWtpnh9PkNTMiMUMv6ehqcFsGbop5Zn+iEWzvAiUZjNtbXKUUrCA
z8w3L4xRbeEesltgHuDBHQ/Ry15R0bLZYzGDKq587Ej2SafjHJyIAxmw+CrmUxpfFBMavL7CKYEJ
fFhGAhYsBGbVHJAg9nJgSKkATVXd1elgZ/NkuobjsFl0g4va4LB7YCRU5qq6KDlYg/BAMmk+lHRc
Ae36u2KTutkVUG8ooq9xwFMW3oULfOtGaKFnnWOBJVTUGtPudzqFXctmvaFvY9CvYlH/uF+/7DKm
s8zda3vGD5WrvMYaSNm3tJVf2shVvGSR6gFbGlOEurd8BqWXuEMalgRinUr1dFPYit3qmxzoW3Gn
QTKDqAF7V7vXUI0M+NUPMPMJuRqB4+gSYkwlOevMOvoOstEGKfZLGmUOnyqHlurKx0w/XFzqew/j
m/dB6QGi3ZtSzN9yLrh5QwVTmcHwhGnTojr6Tf0q4ZIW+yGbV9DXQ9ZM5b4rYJ7hhWhuqJ3qc4+E
grdkubdqXVG94oxzme2URBWLsSjvloGoVR4qH6QUsOl13bTCJrjUpBUT6grU25S5WOa4oTZa1T8+
BOudd7jT9CU83FLMidS/AXPCzZ8="""
SNMP_SPEC = zlib.decompress(base64.b64decode(SNMP_SPEC)).decode('L1')
# Unpack and create asn1tools SNMP Specifications from packed ASN1 text.
SNMP_SPEC = asn1tools.compile_dict(asn1tools.parse_string(SNMP_SPEC))

# System for generating unique RequestID values ------------------------
ID_POOL = set()
ID_LOCK = threading.Lock()


def get_id(minval=1, maxval=0x7FFFFFFF):
    """Returns a new, unique 16-bit identifier."""
    new_id = random.randint(minval, maxval)
    with ID_LOCK:
        while new_id in ID_POOL:
            new_id = (new_id + 1) & maxval
        ID_POOL.add(new_id)
    return new_id


def release_id(old_id):
    """Releases an ID from the pool."""
    with ID_LOCK:
        ID_POOL.discard(old_id)


def clear_ids():
    """Clear all assigned IDs."""
    ID_POOL.clear()


# 64-bit Local Integer for SNMPv3 requests -----------------------------
LOCAL_LOCK = threading.Lock()
LOCAL_INTEGER = random.randint(0, 0xffffffffffffffff)


def get_local_integer():
    """Return current local integer in a thread-safe manner and increment."""
    global LOCAL_LOCK, LOCAL_INTEGER
    with LOCAL_LOCK:
        local_integer = LOCAL_INTEGER
        LOCAL_INTEGER = (local_integer + 1) & 0xffffffffffffffff
    return local_integer


# Global vault for storing localized credentials -----------------------
global_vault = {}
global_vault_lock = threading.Lock()


def add_credentials(engineId, userName, authSecret, privSecret, hashFunc,
                    cipher):
    """Add authentication/privacy credentials to the vault.

    The authentication and privacy secret passwords are localized to the
    given 'engineId' and converted to hashed keys. These keys are stored
    in the global_vault as UsmCredentials using (engineId, userName) as
    the key. Both the 'engineId' and 'userName' must be bytes objects.

    The 'hashFunc' is mandatory and nominally from hashlib and can be:
        md5, sha1, sha224, sha256, sha384, or sha512.

    The 'cipher' is optional and can be any of the following:
        None, DES, AES, or DES3.

    Will raise ValueError if an invalid parameter is passed.
    """
    global global_vault, global_vault_lock
    # Convert the secret passwords to hashed keys, localized to engineId.
    if privSecret:
        privKey = password_to_key(privSecret, engineId, hashFunc)
    else:
        privKey = None
    if authSecret:
        authKey = password_to_key(authSecret, engineId, hashFunc)
    else:
        authKey = None
    if privKey is None and authKey is None:
        raise ValueError("Must provide at least authSecret or privSecret")
    # Store to global vault.
    key = (bytes(engineId), bytes(userName))
    credentials = UsmCredentials(privKey, authKey, hashFunc, cipher)
    with global_vault_lock:
        global_vault[key] = credentials


def get_credentials(engineId, userName):
    """Return credentials stored for given 'engineId' and 'userName'.

    The 'endingId' and 'userName' must be bytes objects. Return `None`
    if no credentials found, otherwise a UsmCredentials named tuple.
    """
    global global_vault, global_vault_lock
    key = (bytes(engineId), bytes(userName))
    with global_vault_lock:
        credentials = global_vault.get(key)
    return credentials


# Helper functions -----------------------------------------------------
def hexlify(data):
    """Python2/3 compatible wrapper for binascii.hexlify."""
    return STR(binascii.hexlify(data))


def parse_address(addrFamily, octets):
    """Parse address from LLDP OID octets given the address family.

    https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
    """
    if addrFamily == 1 and len(octets) > 3:     # IPv4 Address
        address = '.'.join('%s' % octet for octet in octets[-4:])
    elif addrFamily == 2 and len(octets) > 15:  # IPv6 Address
        address = ':'.join('%02x%02x' % pair
                           for pair in zip(*(iter(octets[-16:]),) * 2))
    else:   # Unknown Address Family - Join with dashes
        address = '-'.join('%s' % octet for octet in octets[1:])
    return address


def password_to_key(password, engineID, hashFunc):
    """Return the hash of a password localized to a given snmpEngineID.

    The 'password' must be a string of at least one character.
    The 'engineID' should be a bytes object.
    The 'hashFunc' should be either hashlib.md5 or hashlib.sha1.

    Assuming the following parameters:
        password = 'maplesyrup'
        engineID = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'

    With hashFunc=hashlib.md5 should expect:
    b'Ro^\xed\x9f\xcc\xe2o\x89d\xc2\x93\x07\x87\xd8+'

    With hashFunc=hashlib.sha1 should expect:
    b'f\x95\xfe\xbc\x92\x88\xe3b\x82#_\xc7\x15\x1f\x12\x84\x97\xb3\x8f?'

    Returns a bytearray with a 16-byte MD5 hash or a 20-byte SHA1 hash.
    """
    # Localize the key according to RFC3414 section 2.6. (takes ~0.3 ms)
    password = BYTES(password)
    if not password:
        raise ValueError("Password cannot be blank")
    if not engineID:
        raise ValueError("Invalid engineID")
    # Create 1MB buffer with repeating password and hash (fast, releases GIL).
    buffer = memoryview(password * ((2**20 // len(password)) + 1))
    privHash = hashFunc(buffer[:2**20]).digest()
    # Localize the key to the engineID and return the hash as a bytearray.
    return bytearray(hashFunc(privHash + engineID + privHash).digest())


def get_cipher_DES(privKey, salt):
    """Return a DES cipher object initialized from given key and salt.

    The DES blocksize is 64bits (8 bytes) in Cipher Block Chain mode.
    'privKey' must be at least 16 bytes to split into key and pre-IV.
    """
    # First 8 bytes of the privacy key is used as the DES key.
    key = privKey[:8]
    # Next 8 bytes of the privacy key is XOR'd with salt to get IV.
    pre_iv = bytearray(privKey[8:16])
    salt = bytearray(salt)
    iv = bytearray(a ^ b for a, b in zip(pre_iv, salt))
    # Return DES cipher in cipher block chaining mode.
    return DES.new(key, DES.MODE_CBC, iv=iv)


def decrypt_message(ciphertext, privKey, cipher, engineBoots, engineTime,
                    salt):
    """Decrypt 'ciphertext' with given 'cipher' and return result.

    The 'privKey' must contain at least 16 bytes.
    If the 'cipher' is None, the ciphertext is returned unmodified.
    The 'salt' is from the msgPrivacyParameters of the message.
    The 'engineBoots' and 'engineTime' is only used for the AES cipher.

    Will raise ValueError if 'privKey' or 'salt' are not the correct
    size or 'ciphertext' is not a multiple of the DES block size.
    """
    if not cipher:
        return ciphertext
    if not privKey or len(privKey) < 16:
        raise ValueError("Privacy key must be at least 16 bytes")
    if not salt or len(salt) != 8:
        raise ValueError("Expected 8-byte salt value got %s" % repr(salt))
    if cipher is DES:
        # DES Cipher Block Chain. Blocksize is 64bits (8 bytes). Enforce this.
        if len(ciphertext) % 8 != 0:
            raise ValueError("ciphertext is not a multiple of DES blocksize")
        # Initialize cipher key as first 8 bytes of privKey.
        cipher = get_cipher_DES(privKey, salt)
    elif cipher is AES:
        # AES Cipher Feed-Back. Construct initialization vector.
        iv = struct.pack('!ll', engineBoots & 0x7fffffff,
                         engineTime & 0x7fffffff) + salt
        # Create cipher using first 16-bytes of privKey as the AES key.
        cipher = AES.new(privKey[:16], AES.MODE_CFB, iv=iv, segment_size=128)
    else:
        raise ValueError("Unsupported cipher %s" % repr(cipher))
    return cipher.decrypt(ciphertext)


def encrypt_message(data, privKey, cipher, engineBoots, engineTime):
    """Encrypt the given data with the cipher and return the result.

    The 'privKey' must contain at least 16 bytes.
    If the 'cipher' is None, the ciphertext is returned unmodified.
    A random local integer is grabbed automatically and along with the
    'engineBoots' and 'engineTime' values is used to generate the salt.

    Will raise ValueError if the cipher is not recognized or the
    privKey is not at least 16 bytes.

    Returns a 2-tuple of (ciphertext, salt) where 'ciphertext' is the
    encrypted message, and 'salt' is the 8-byte salt value.
    """
    if not cipher:
        return data
    if not privKey or len(privKey) < 16:
        raise ValueError("Privacy key must be at least 16 bytes")
    # Grab the next available local integer value and increment.
    localInteger = get_local_integer()
    if cipher is DES:
        # DES Cipher Block Chain. Pad data to blocksize of 64bits (8 bytes).
        plaintext = data + (b'\x00' * (8 - len(data) % 8))
        # Construct salt from engineBoots and localInteger.
        salt = struct.pack('!lL', engineBoots & 0x7fffffff,
                           localInteger & 0xffffffff)
        cipher = get_cipher_DES(privKey, salt)
    elif cipher is AES:
        # AES Cipher Feed Back mode. No padding necessary.
        plaintext = data
        # Construct 16-byte initialization vector.
        iv = struct.pack('!llQ', engineBoots & 0x7fffffff,
                         engineTime & 0x7fffffff, localInteger)
        salt = struct.pack('!Q', localInteger)
        cipher = AES.new(privKey[:16], AES.MODE_CFB, iv=iv, segment_size=128)
    else:
        raise ValueError("Unsupported cipher %s" % repr(cipher))
    # Return 2-tuple of (ciphertext, salt).
    return cipher.encrypt(plaintext), salt


def authenticate_message(data, authKey, hashFunc, current_hmac):
    """Calculate and return HMAC of entire serialized SNMPv3 message.

    The 'data' must be a BER serialization of an SNMPv3 message.
    The 'current_hmac' must be a bytes object containing the current
    msgAuthenticationParameters value of the message. The position of
    this value is found, and the HMAC is calculated as if these
    bytes were zeros. Also sets the truncation size of the HMAC.

    Will raise ValueError if the current_hmac cannot be found.

    Returns a 2-tuple of (pos, hmac) where 'pos' is the byte position
    of the 'current_hmac' value and 'hmac' is the calculated HMAC.
    """
    # http://en.wikipedia.org/wiki/HMAC (MD5 Takes 6.7us of 136 byte message).
    hmac_size = len(current_hmac)
    # Search string = 0x04 (OCTET STRING) + length + current HMAC value
    pos = data.find(struct.pack('BB', 0x04, hmac_size) + current_hmac)
    if pos < 0:
        raise ValueError("Could not find msgAuthenticationParameters position")
    pos += 2
    # Instantiate keys based on chosen hash function (to get block size).
    K1 = hashFunc()
    K2 = hashFunc()
    # Extend the authentication key to hashFunc blocksize by appending zeros.
    extendedAuthKey = authKey + (b'\x00' * (K1.block_size - len(authKey)))
    # XOR extended key with 0x36 (IPAD) and 0x5c (OPAD) to start K1, K2 hashes.
    K1.update(extendedAuthKey.translate(IPAD))
    K2.update(extendedAuthKey.translate(OPAD))
    # Dump message with HMAC zeroed out into K1.
    K1.update(data[:pos] + (b'\x00' * hmac_size) + data[pos + hmac_size:])
    # Dump digest of K1 into K2.
    K2.update(K1.digest())
    # Truncate digest to HMAC size.
    hmac = K2.digest()[:hmac_size]
    # Return HMAC position, and newly calculated HMAC value.
    return pos, hmac


# timeit(setup="import asnmp;import binascii;import hashlib;snmpEngineID = binascii.unhexlify('800001dc03000299152ed5');authKey = asnmp.password_to_key('5288sandbox', snmpEngineID, hashlib.md5);wholeMsg = binascii.unhexlify('308185020103300f0202266f020300ffe3040107020103043d303b040b800001dc03000299152ed5020101020200a1040d61646d696e6973747261746f72040ca0a45be24b83a053194712b20408000000018b7fb38504305b3aa2bb8ea40ecd6bb28f23c4dd5d53e71d3b5ac06278a594211a88ca7fa4549731f154b7cf8129dbbbedb74da3295e');msgAuthenticationParameters = binascii.unhexlify('a0a45be24b83a053194712b2')", stmt="asnmp.authenticate_message(wholeMsg, authKey, hashlib.md5, msgAuthenticationParameters)", number=100)
# ----------------------------------------------------------------------
class SnmpMessage(object):
    """Class to encode and decode an SNMP v1/v2c/v3 message (datagram).

    'oids' must be a list of 2-tuples as: [(oid, value), ...]
           The errorIndex in the reply might index this list.
    'pduType' must be the PDU type name. One of:
            'get-request', 'get-next-request', 'get-response',
            'set-request', 'trap', 'get-bulk-request',
            'inform-request', 'snmpV2-trap', 'report'.
    'version' is 0 for SNMPv1, 1 for SNMPv2c, or 3 for SNMPv3.
    'encoding' is the encoding to use when decoding SNMP octet-strings.
               It defaults to 'latin_1'.

    SNMPv1 specific attributes:
    'community' is the community string.

    SNMPv3 specific attributes:
    'msgId' is the message ID (no longer uses the PDU requestId).
    'maxSize' is the maximum size message this service can handle.
    'flags' is a combination of REPORT_FLAG, PRIV_FLAG, AUTH_FLAG.
    'securityModel' is 0=any, 1=SNMPv2, 2=SNMPv3, 3=USM
    'usmSecurity' is either None or a UsmSecurity named 6-tuple.
    'credentials' is either None or a UsmCredentials named 4-tuple.
                  This is required for encryption (PRIV_FLAG set) or
                  authentication (AUTH_FLAG set). If not specified,
                  will attempt to retrieve from global_vault using
                  usmSecurity engineId and userName.
    'contextEngineId' is the context engine ID as raw bytes.
    'contextName' is the context name as a string.

    If 'datagram' is supplied, all other arguments are ignored and the
    raw SNMP datagram is decoded instead (may raise ValueError).
    """
    # SNMP errorStatus mapping from RFC 3416 'error-status'.
    ERRORS = {
        0: ("noError", "No error occurred"),
        1: ("tooBig", "The PDU size was too big for the agent"),
        2: ("noSuchName", "An OID didn't exist"),
        3: ("badValue", "A set request specified an incorrect value type"),
        4: ("readOnly", "A set request was attempted on a read-only OID"),
        5: ("genericError", "The value of the OID could not be retrieved"),
        6: ("noAccess", "An OID was not accessible"),
        7: ("wrongType", "A value was the wrong type for a variable"),
        8: ("wrongLength", "A value was the wrong length for a variable"),
        9: ("wrongEncoding", "A value used the wrong ASN.1 encoding"),
        10: ("wrongValue", "This value cannot be assigned to the variable"),
        11: ("noCreation", "The OID does not exist and could not be created"),
        12: ("inconsistentValue", "The value is inconsistent with other OIDs"),
        13: ("resourceUnavailable", "Not enough resources to assign the value"),
        14: ("commitFailed", "Values OK but one or more sets failed. All "
             "assignments were successfully undone."),
        15: ("undoFailed", "Values OK but one or more sets failed. Could not "
             "undo all assignments"),
        16: ("authorizationError", "Authorization failed"),
        17: ("notWritable", "Variable exists but the agent cannot modify it"),
        18: ("inconsistentName", "The OID does not exist and it cannot be "
             "created because of an inconsistent name"), }
    # Error OIDs returned when errorStatus is set from RFC 3418.
    ERROR_OIDS = {
        "1.3.6.1.6.3.15.1.1.4.0": "Unknown Engine ID",      # RFC3414 3.2(3)
        "1.3.6.1.6.3.15.1.1.3.0": "Unknown user name",      # RFC3414 3.2(4)
        "1.3.6.1.6.3.15.1.1.1.0": "Unsupported security level",  # RFC3414 3.2(5)
        "1.3.6.1.6.3.15.1.1.5.0": "Authentication digest wrong",  # RFC3414 3.2(6)
        "1.3.6.1.6.3.15.1.1.2.0": "Not in time window",     # RFC3414 3.2(7)
        "1.3.6.1.6.3.15.1.1.6.0": "Decryption error",       # RFC3414 3.2(8)
    }
    # HMAC sizes given algorithm.
    HMAC_SIZES = {md5: 12,          # HMAC96-MD5128  (RFC 3414)
                  sha1: 12,         # HMAC96-SHA160  (RFC 3414)
                  sha224: 16,       # HMAC128-SHA224 (RFC 7860)
                  sha256: 24,       # HMAC192-SHA256 (RFC 7860)
                  sha384: 32,       # HMAC256-SHA384 (RFC 7860)
                  sha512: 48, }     # HMAC384-SHA512 (RFC 7860)
    # Mapping of a UsmSecurity tuple to actual SNMPv3Message names.
    USM_KEYS = ('msgAuthoritativeEngineID', 'msgAuthoritativeEngineBoots',
                'msgAuthoritativeEngineTime', 'msgUserName',
                'msgAuthenticationParameters', 'msgPrivacyParameters')

    def __init__(self, oids=[], version=0, community=None, pduType=None,
                 requestId=None, errorStatus=0, errorIndex=0, maxSize=65535,
                 flags=REPORT_FLAG, securityModel=3, encoding='latin_1',
                 usmSecurity=DEFAULT_USM_SECURITY, contextEngineId=b'',
                 msgId=None, contextName=b'', credentials=None, datagram=None):
        """Initialize packet with oids list or raw datagram."""
        self.encoding = encoding
        # Sanitize and save supplied message values.
        self.version = int(version)
        self.community = community
        self.pduType = pduType
        self.requestId = requestId           # None=auto-assign.
        self.errorStatus = int(errorStatus)  # Also used for non-repeaters.
        self.errorIndex = int(errorIndex)    # Also used for max-repetitions.
        self.error = ""                      # Fatal error description string.
        self.failed = {}                     # v1/v3 failed OIDs: {OID: reason}
        # SNMPv3 specific parameters.
        self.msgId = msgId                  # None=auto-assign
        self.maxSize = int(maxSize)
        self.flags = int(flags) & 0xff
        self.securityModel = int(securityModel)
        self.contextEngineId = BYTES(contextEngineId, self.encoding)
        self.contextName = contextName
        self.credentials = credentials
        self.timestamp = time.time()        # Packet creation timestamp.
        if self.version == 3 and self.securityModel == 3:
            # Set User-base Security Model values trying to flag errors.
            self.usmSecurity = UsmSecurity(
                engineId=BYTES(usmSecurity[0], self.encoding),
                engineBoots=int(usmSecurity[1]),
                engineTime=int(usmSecurity[2]),
                userName=BYTES(usmSecurity[3], self.encoding),
                hmac=BYTES(usmSecurity[4], self.encoding),
                salt=BYTES(usmSecurity[5], self.encoding))
        else:
            self.usmSecurity = usmSecurity
        self.varBindList = []
        self.requestOids = oids
        # Are we decoding from datagram, or encoding from init arguments?
        if datagram:
            # Decoding datagram bytes into packet.
            self.decode(datagram)
        else:
            # Encoding parameters. Verify parameters are valid.
            if not community and self.version in (0, 1):
                raise ValueError("Community string required for SNMP v1/v2c")
            if not pduType:
                raise ValueError("Must specify PDU type to use")
            if credentials and len(credentials) != 4:
                raise ValueError("credentials must 4-tuple of (privKey, "
                                 "authKey, hashFunc, cipher)")

    def get_datagram(self):
        """Required by UdpThread. Return the raw datagram of the packet.

        May raise ValueError if the contents cannot be encoded.
        """
        # Todo: We maybe should not re-encode if we've been paused?
        datagram = self.encode()
        return datagram

    def get_id(self):
        """Required by UdpThread. Returns the unique ID of this message.

        For SNMP v1/v2c it is self.requestId of the PDU.
        For SNMP v3 it is self.msgId. The PDU requestID may be encrypted.
        """
        ID = self.msgId if self.version == 3 else self.requestId
        if ID is None:
            raise RuntimeError("get_id: No ID. Must call get_datagram() first")
        return ID

    def clear_id(self):
        """Clears the requestId of the packet."""
        if self.requestId:
            release_id(self.requestId)
            self.requestId = None

    def get_error(self):
        """Required by UdpOperation. Return the message's error status."""
        return self.error

    def get_engine_info(self):
        """Return SNMPv3 user security engine information, if it exists.

        Will return `None` for SNMPv1/v2c messages or if the security
        model is not USM. Otherwise returns an EngineInfo named tuple.
        """
        if self.version != 3 or self.securityModel != USM:
            return None
        if not self.usmSecurity:
            return None
        return EngineInfo(
            self.usmSecurity.engineId, self.usmSecurity.engineBoots,
            self.usmSecurity.engineTime, self.timestamp)

    def encode(self):
        """Encode ourselves into a packet and return packet bytes.

        Obtains a new unique requestId, releasing the previous one if it
        was set. Called when packet is first sent, or upon a retry.
        Will raise ValueError if self.requestOids cannot be converted to
        varBinds, or if the packet cannot be encoded.
        """
        # Release current request_id (if may exist if this is a retry)
        # and set a new one. Takes approx 0.012 milliseconds
        self.clear_id()
        self.requestId = get_id() if self.requestId is None else self.requestId
        # Generate varBindList and assign to PDU. Can take 50-100ms.
        if not self.varBindList:
            # Allow ValueError to be raised on bad requestOids format.
            self.varBindList = self.oids_to_varbinds(self.requestOids)
        if self.pduType == 'get-bulk-request':
            # GetBulkRequest renames error vars to repetitions vars.
            pdu = {'request-id': self.requestId,
                   'non-repeaters': self.errorStatus,
                   'max-repetitions': self.errorIndex,
                   'variable-bindings': self.varBindList}
        else:
            # Normal PDU.
            pdu = {'request-id': self.requestId,
                   'error-status': self.errorStatus,
                   'error-index': self.errorIndex,
                   'variable-bindings': self.varBindList}
        # Generate message depending on version (v1/v2c versus v3).
        if self.version == 3:
            # Generate SNMPv3 scopedPDU
            scopedPDU = {'contextEngineID': self.contextEngineId,
                         'contextName': BYTES(self.contextName, self.encoding),
                         'data': (self.pduType, pdu)}
            # By default we simply embed the PDU.
            msgData = ('plaintext', scopedPDU)
            msgSecurityParameters = b''
            # If we are doing encryption or authentication it is more complex.
            if self.flags & (PRIV_FLAG | AUTH_FLAG):
                if self.securityModel != 3:
                    raise ValueError("Unsupported security model %s" %
                                     self.securityModel)
                # Unpack user-based security model parameters.
                (engineId, engineBoots, engineTime, userName, hmac,
                 salt) = self.usmSecurity
                # Try to get credentials, if not already provided.
                if not self.credentials:
                    self.credentials = get_credentials(engineId, userName)
                if not self.credentials:
                    raise ValueError("No credentials to encrypt/authenticate "
                                     "for engineId 0x%s and username %r" %
                                     (hexlify(engineId), userName))
                # If authenticate flag is set, put placeholder in parameters.
                if self.flags & AUTH_FLAG:
                    hmac_len = self.HMAC_SIZES.get(self.credentials.hashFunc, 0)
                    hmac = b'\x00' * hmac_len
                # If privacy flag is set perform encryption.
                if self.flags & PRIV_FLAG:
                    # BER encode the PDU to octetstring for encryption.
                    try:
                        encodedPDU = SNMP_SPEC.encode('ScopedPDU', scopedPDU)
                    except (TypeError, AttributeError) as err:
                        # Raise ValueError to fail this encode.
                        traceback.print_exc()
                        raise ValueError("Invalid OID or value: %s" % str(err))
                    # Encrypt the PDU. Raises ValueError on invalid parameters.
                    ciphertext, salt = encrypt_message(
                        encodedPDU, self.credentials.privKey,
                        self.credentials.cipher, engineBoots, engineTime)
                    # Update msgData to encrypted CHOICE.
                    msgData = ('encryptedPDU', ciphertext)
                # Update self.usmSecurity.
                self.usmSecurity = UsmSecurity(
                    engineId, engineBoots, engineTime, userName, hmac, salt)
            # Encode USM parameters if security model is USM.
            if self.securityModel == USM:
                usmMapping = dict(zip(self.USM_KEYS, self.usmSecurity))
                msgSecurityParameters = SNMP_SPEC.encode(
                    "UsmSecurityParameters", usmMapping)
            # Generate SNMPv3 'SNMPv3Message'
            msg_type = 'SNMPv3Message'
            self.msgId = self.requestId if self.msgId is None else self.msgId
            msgGlobalData = {'msgID': self.msgId, 'msgMaxSize': self.maxSize,
                             'msgFlags': struct.pack('B', self.flags),
                             'msgSecurityModel': self.securityModel}
            message = {'msgVersion': self.version,
                       'msgGlobalData': msgGlobalData,
                       'msgSecurityParameters': msgSecurityParameters,
                       'msgData': msgData}
        else:
            # Generate SNMPv1/v2c 'Message'.
            msg_type = 'Message'
            message = {'version': self.version,
                       'community': BYTES(self.community, self.encoding),
                       'data': (self.pduType, pdu)}
        # Encode message using asn1tools Basic Encoding Rules.
        try:
            datagram = SNMP_SPEC.encode(msg_type, message, check_types=False)
        except (TypeError, AttributeError) as err:
            traceback.print_exc()
            raise ValueError("Invalid OID or value: %s" % str(err))
        # If this is an SNMP v3 message with authentication, do that now.
        if (self.version == 3 and self.securityModel == USM and
                self.flags & AUTH_FLAG):
            # Privacy flag set. Authenticate message.
            privKey, authKey, hashFunc, cipher = self.credentials
            print("Authenticating message: hashFunc=%r, hmac=%r" % (hashFunc, hmac))
            pos, hmac = authenticate_message(datagram, authKey, hashFunc, hmac)
            # Returned patched, authenticated datagram.
            return datagram[:pos] + hmac + datagram[pos + len(hmac):]
        return datagram

    def decode(self, datagram):
        """Detect SNMP datagram version and decodeDecode raw SNMP datagram bytes into object.

        Will raise ValueError on an invalid packet or unexpected format.
        """
        # Detect the version of this message.
        try:
            detect = SNMP_SPEC.decode('MessageVersion', datagram)
        except asn1tools.errors.Error as err:
            raise ValueError("Unable to decode packet: %s" % str(err))
        self.version = detect.get('version')
        self.timestamp = time.time()
        if self.version in (0, 1):
            self.decode_v12(datagram)
        elif self.version == 3:
            self.decode_v3(datagram)
        else:
            raise ValueError("Unknown SNMP version byte 0x%02x" % self.version)

    def decode_v12(self, datagram):
        """Decode raw SNMP v1 or v2c bytes with ASN.1 BER into packet.

        Will raise ValueError on an invalid packet or unexpected format.
        """
        # Decode the SNMP v1/v2c message using asn1tools.
        try:
            message = SNMP_SPEC.decode('Message', datagram)
        except asn1tools.errors.Error as err:
            raise ValueError("Unable to decode packet: %s" % str(err))
        # Message is a dictionary with keys ('version', 'data', 'community')
        self.community = STR(message.get('community'), self.encoding)
        # Clear SNMPv3 attributes
        self.maxSize = self.flags = self.securityModel = 0
        self.msgSecurityParameters = b''
        self.contextEngineId = self.contextName = b''
        self.msgId = self.usmSecurity = self.credentials = None
        # Parse PDU
        data = message.get('data')
        self.parse_PDU(data)

    def decode_v3(self, datagram):
        """Decode raw SNMP v3 bytes with ASN.1 BER and parse into packet.

        Will raise ValueError on an invalid packet or unexpected format.
        """
        # Decode the SNMP v3 message using asn1tools.
        try:
            message = SNMP_SPEC.decode('SNMPv3Message', datagram)
        except asn1tools.errors.Error as err:
            raise ValueError("Unable to decode SNMP v3 packet: %s" % str(err))
        # Clear SNMPv1 attributes.
        self.community = None
        # Unpack and verify SNMPv3 global header data.
        globalData = message.get('msgGlobalData')
        if not globalData or type(globalData) is not dict:
            raise ValueError("Invalid msgGlobalData in SNMP v3 packet")
        self.msgId = globalData.get('msgID')
        self.maxSize = globalData.get('msgMaxSize')
        msgFlags = globalData.get('msgFlags', b'\x00')
        self.flags = struct.unpack_from('B', msgFlags)[0]
        self.securityModel = globalData.get('msgSecurityModel')
        # Try to ASN.1 decode USM security parameters, if they exist.
        self.msgSecurityParameters = message.get('msgSecurityParameters')
        pduFormat, scopedPDU = message.get('msgData', (None, None))
        if self.securityModel == 3:
            # Unpack User Security Model values from security parameters.
            try:
                params = SNMP_SPEC.decode('UsmSecurityParameters',
                                          self.msgSecurityParameters)
            except asn1tools.errors.Error as err:
                raise ValueError("Unable to decode SNMP v3 USM security "
                                 "parameters: %s" % str(err))
            usmParams = tuple(params.get(key) for key in self.USM_KEYS)
            self.usmSecurity = UsmSecurity(*usmParams)
            engineId, engineBoots, engineTime, userName, hmac, salt = usmParams
            # Try to grab credentials from global authentication vault.
            self.credentials = global_vault.get((engineId, userName))
            # if PDU is encrypted, decrypt it now.
            if pduFormat == 'encryptedPDU':
                if self.flags & PRIV_FLAG == 0:
                    raise ValueError("Encrypted PDU without PRIV flag set")
                if not self.credentials:
                    raise ValueError("No credentials to decrypt for engineId "
                                     "0x%s and username %r" %
                                     (hexlify(engineId), userName))
                # Decrypt and attempt to BER decode the encrypted PDU.
                privKey, authKey, hashFunc, cipher = self.credentials
                try:
                    encodedPDU = decrypt_message(scopedPDU, privKey, cipher,
                                                 engineBoots, engineTime, salt)
                    scopedPDU = SNMP_SPEC.decode('ScopedPDU', encodedPDU)
                except (ValueError, asn1tools.errors.Error) as err:
                    raise ValueError("Unable to decrypt packet: %s" % str(err))
            # If PDU required authentication, check it now.
            if self.flags & AUTH_FLAG:
                privKey, authKey, hashFunc, cipher = self.credentials
                pos, msgHMAC = authenticate_message(
                    datagram, authKey, hashFunc, hmac)
                if msgHMAC != hmac:
                    raise ValueError("Authentication failed username %r. "
                                     "Message HMAC=%s, Calculated HMAC=%s" %
                                     (userName, hexlify(hmac), hexlify(msgHMAC)))
        else:
            # Some other security model. Raise error if encrypted.
            self.usmSecurity = None
            self.credentials = None
            if pduFormat != 'plaintext' or self.flags & PRIV_FLAG:
                raise ValueError("Cannot decrypt security model %s" %
                                 self.securityModel)
            if self.flags & AUTH_FLAG:
                raise ValueError("Cannot authenticate security model %s"
                                 % self.securityModel)
        # Extract parameters from ScopedPDU and decode PDU.
        self.contextEngineId = scopedPDU.get('contextEngineID')
        self.contextName = scopedPDU.get('contextName')
        data = scopedPDU.get('data')
        self.parse_PDU(data)

    def parse_PDU(self, data):
        """Parse the PDUs 'data' object into self.oids.

        'data' should be a PDUs CHOICE tuple of (pduType, body).
        """
        if data and len(data) == 2:
            # Body is a dictionary with keys ('request-id', 'error-status',
            # 'error-index', 'variable-bindings')
            self.pduType, body = data
            self.requestId = body.get('request-id')
            self.errorStatus = body.get('error-status')
            self.errorIndex = body.get('error-index')
            self.varBindList = body.get('variable-bindings')
        else:
            raise ValueError("Malformed SNMP packet PDU: %s" % repr(data))
        # Convert errorStatus to string. Expect '' if errorStatus=0 (no error).
        if self.errorStatus == 0:
            self.error = ''
        else:
            error_strings = self.ERRORS.get(self.errorStatus)
            if not error_strings:
                self.error = "Unknown Error (%s)" % self.errorStatus
            else:
                self.error = "%s - %s" % error_strings
        # Convert varBindList to python objects.
        self.oids = self.varbinds_to_oids(self.varBindList)

    def oids_to_varbinds(self, oids):
        """Convert oids list of (oid, value) tuples to asn1tools varBinds.

        Will raise ValueError if an OID cannot be converted.
        """
        # Pack oids to asn1tools variable-bindings list.
        varBindList = []
        for pos, (oid, value) in enumerate(oids):
            # Value is a tuple of (syntax, (type, value))
            # syntax can be 'simple' or 'application-wide'
            # 'simple' types are 'number', 'string', 'object', 'empty'.
            # 'application-wide' types are 'address', 'counter', 'gauge',
            #                              'ticks', 'arbitrary'.
            # Value is always None for get-request PDU types.
            if value is None:
                syntax = 'empty'
            elif isinstance(value, NUMBER_TYPES):
                syntax = 'number'
            elif isinstance(value, bytes):
                syntax = 'string'
            elif isinstance(value, TEXT_TYPES):
                # Python2 'unicode' and Python3 'str' must be encoded to bytes.
                syntax = 'string'
                value = BYTES(value, self.encoding)
            else:
                raise ValueError("Unrecognized value type at oids[%d]" % pos)
            asn_value = ('simple', (syntax, value))
            varBindList.append({'name': oid, 'value': asn_value})
        return varBindList

    def varbinds_to_oids(self, varBindList):
        """Unpack asn1tools varBindList and return a list of 2-tuples.

        For SNMP v2/v3 will populate self.failed with failed OIDs as:
            { OID: reason }

        Will raise ValueError if an invalid varBind is discovered.
        """
        # Convert varBindList, a list of {'name', 'value'} to oids.
        oids = []
        for varBind in varBindList:
            oid, syntax = varBind.get('name'), varBind.get('value')
            # 'syntax' must be a CHOICE 2-tuple of (syntax_type, value)
            if oid and syntax and type(syntax) is tuple and len(syntax) == 2:
                # syntax_type can be: 'simple', 'application-wide'
                # SNMP v3 adds: 'unSpecified', 'noSuchObject',
                #               'noSuchInstance', 'endOfMibView'.
                syntax_type, value = syntax
                # If value is a CHOICE 2-tuple, unpack it now.
                if value and type(value) is tuple and len(value) == 2:
                    # Unpack a CHOICE value 2-tuple of (asn1type, value)
                    asn1type, value = value
                    # The various 'syntax' 'asn1type's defined are:
                    # 'simple' syntax: 'number', 'string', 'object', 'empty'.
                    # 'application-wide' syntax: 'address', 'counter',
                    #              'gauge', 'ticks', 'arbitrary', 'counter64'.
                    # asn1tools automatically wraps them to Python natives.
                    if self.encoding and asn1type == 'string':
                        # Decode OCTET-STRING using specified encoding.
                        value = STR(value, self.encoding)
                    oids.append((oid, value))
                else:
                    # SNMP v2/v3 OID failed to fetch. Instead of setting
                    # errorStatus and errorIndex like SNMP v1, these
                    # versions of SNMP return the OID with value=None and
                    # error_syntax either 'unSpecified', 'noSuchObject',
                    # 'noSuchInstance', or 'endOfMibView'. Add to failed.
                    self.failed[oid] = syntax_type
        return oids
#end class SnmpMessage(object)


class UdpOperation(object):
    """Base class used by UdpThread to manage a single UDP request/reply.

    Manages a 'request' and provides a 'reply'. Both are packet classes
    which must implement the following methods:
        get_datagram() -> Returns the raw datagram of the packet
        get_id() -> Returns the unique transaction ID of the packet.
        clear_id() -> Releasees the unique transaction ID of the packet.
        encode() -> Re-encodes the datagram with a new transaction ID.

    The operation takes the following parameters:
        retries = Number of times to retry the operation if the initial
                  attempt times out without a reply. Default 1.
        timeout = Timeout in seconds for each attempt.
        max_pending = Maximum number of operations to have ongoing to a
                      specific host. Defaults to 1.
        queue = A Queue to add the operation to when it is finished.
        callback = A function to call when finished. Will call with
                   the operation as the single argument.

    As the operation is processed the following attributes are updated:
        self.count = Number of packets sent (attempts).
        self.active = True if the thread is currently processing this.
        self.finished = True once the thread finishes the operation.
        self.started = Time the operation was started.
        self.timestamp = Time last packet was sent (updated each retry).

    Once the request is complete, the following attributes will be set:
        self.elapsed = Time from sending the request to getting a reply.
        self.reply = The decoded reply packet.
        self.ok = True if the reply was received with no errors.
        self.error = Error string if self.ok is False.
        self.warnings = Non-fatal errors encountered in the operation.
    """
    def __init__(self, host, port, retries=1, timeout=2.0, queue=None,
                 callback=None, max_pending=1):
        # Sanitize and set parameters
        self.host = STR(host)
        self.port = int(port)
        self.retries = int(retries)
        if self.retries < 0:
            raise ValueError("Invalid retries specified %r" % retries)
        self.timeout = float(timeout)
        if self.timeout < 0:
            raise ValueError("Invalid timeout specified %s" % timeout)
        self.max_pending = int(max_pending)
        self.queue = queue
        self.callback = callback
        # Set response attributes.
        self.count = 0                  # Number of times the message was sent.
        self.active = False             # True while operation is processing.
        self.finished = False           # True when operation is completed.
        self.started = False            # Time the operation was started.
        self.timestamp = None           # Time the request was sent at.
        self.elapsed = 0                # Time elapsed for this operation.
        self.reply = None               # Reply SnmpPacket object.
        self.ok = False                 # True if successful response received.
        self.error = ""                 # Error associated with the response.
        self.warnings = []              # Non-fatal issues with the operation.

    def get_address(self):
        """Return the address as a tuple of (host, port)"""
        return (self.host, self.port)

    def get_datagram(self, engines=None):
        """Return the current request packet's datagram.

        May raise ValueError if the encoding of the datagram fails.
        """
        return self.request.get_datagram()

    def get_id(self):
        """Return the unique transaction ID of the current request."""
        return self.request.get_id()

    def start(self):
        """Start this operation. Called before packet is transmitted."""
        # Increase transmit count and set active/finished flags.
        self.count += 1
        self.active = True
        self.finished = False
        # If this is the first transmission set the start timestamp.
        if not self.timestamp:
            self.started = time.time()
            self.timestamp = self.started

    def pause(self):
        """Pause the operation. Called if packet transmission was delayed.

        This can happen if the transmit socket buffer is full.
        """
        self.count -= 1
        self.active = False
        self.timestamp = None

    def poll(self):
        """Check for timeout. Called occasionally by UdpThread.

        Return error string if operation failed, or False if no error.
        """
        elapsed = abs(time.time() - self.timestamp)
        if elapsed > self.timeout:
            # We are timed out.
            return "Timed out %0.1f sec." % self.timeout
        # No error.
        return False

    def retry(self):
        """Reconfigure packet to be resent. Generate new request.

        Return True if successful, False if retry limit exceeded.
        """
        # Did we exceed our retry limit? (Original send doesn't count).
        if self.count < (self.retries + 1):
            # Reset our packet transmission timestamp.
            self.timestamp = time.time()
            return True
        else:
            return False

    def receive(self, reply):
        """Called by UdpThread when a reply received with matching ID.

        'reply' will be the message object.

        Should return True if this operation is done, or False if we
        need to send another packet and have reconfigured to do so.
        """
        # print("UDPOperation.receive(reply.error=%s)" % repr(reply.error))
        self.reply = reply
        if reply.get_error():
            self.error = reply.get_error()
        return True

    def finish(self, error=''):
        """Called by UdpThread to complete the operation.

        Releases the request_id of the request packet.
        Sets self.finished to True, and if self.queue was specified adds
        ourselves to it. If self.callback was specified, calls it.
        """
        self.request.clear_id()
        # Set operation status.
        self.elapsed = abs(time.time() - self.started)
        self.timestamp = None
        self.ok = False
        # Set error, if specified, otherwise leave possible packet error alone.
        if error:
            self.error = error
        self.ok = True if not self.error else False
        # Allow finishing tasks to be performed.
        self.handle_finish()
        self.active = False
        self.finished = True
        # Add ourselves to the queue if it was specified.
        if self.queue:
            self.queue.put(self)
        # If a callback function was specified, call it now.
        if callable(self.callback):
            self.callback(self)

    def handle_finish(self):
        """Can be sub-classed. Called when the operation completes but
        before self.finished is set to True and before any callbacks."""
        pass
#end class UdpOperation(object)


class SNMPOperation(UdpOperation):
    """Holds and tracks a single SNMP v1/v2c/v3 Get message to an agent.

    Operation parameters:
    'host' is the IP address/hostname of the agent to contact.
    'port' is the UDP port number on the host to send the message to.
    'retries' is the number of times to retry the operation if the
              initial attempt times out without a reply. Default 1.
    'timeout' is the timeout in seconds for each attempt.
    'max_pending' is the maximum number of operations to have ongoing to
                  this host. Defaults to 1.
    'queue' is an Queue to add the operation to when it is finished.
    'callback' is a function to call when finished. Will call with
               the operation as the single argument.

    SNMP common and PDU parameters:
    'oids' is a list of OIDs to set as: [ (oid, value), ... ]
    'pduType' can be one of: 'get-request', 'get-next-request',
              'get-bulk-request', 'set-request', 'report'.
    'version' defaults to 0 for SNMP v1 (1=SNMP v2 and 3=SNMP v3).
    Bulk requests have two additional parameters:
    'non_repeaters' the first X number of OIDs will be walked only once
                    and return a single result in the response.
    'max_repetitions' the remainder of the OIDs will be walked this many
                      times, each one producing this many results.

    SNMP v1/v2c parameters (version=0 or 1):
    'community' string is required for SNMP v1/v2c.

    SNMP v3 parameters (ignored unless version=3):
    'maxSize' defaults to 65535. Should not need to be changed.
    'engineId' is the engine ID of the target host. Leave blank to
               perform auto-discovery.
    'contextName' is used by some SNMP agents as a way of targeting a
                  particular instance of a MIB (eg. VLAN 33). If not
                  used it should be left as a blank string (default).
    'securityModel' defaults to USM (3). Can also be ANY (0), SNMPv1 (1),
                    or SNMPv2c (2). TSM (4) currently not supported.
                    For USM (3), these parameters also need to be set:
        'userName' = The string username (required)
        'authSecret' = Passphrase for authentication or `None` for no auth.
        'hashFunc' = `None` or md5 (default) or sha1, sha224, etc.
        'privSecret' = Passphrase for privacy or `None` for no privacy.
        'cipher' = Privacy cipher. Default is DES but can be AES.

    The parameters result in an SNMP message and PDU stored in:
    self.message

    The operation sends this message to the host and wait for the
    specified timeout for a response. If no response is received, it
    will attempt to resend 'retries' amount of times. Because the
    transport is UDP and packet loss is somewhat expected it is
    recommended 'retries' never be set less than 1.

    If version=3 (SNMPv3) and USM security is being used, the host's
    'engineId' is required to generate the message. If this is not
    provided, self.DISCOVERY_MESSAGE is sent to the host. The response
    should contain the host's 'engineId' which will then be cached and
    used the generate the message.

    The operation is initialized with the following attributes:
        self.requestOids = A dictionary of { OID: value } of the OIDs
                           that were part of the original request.
        self.message = The last SnmpMessage() sent to self.host
    Once complete, the operation will yield:
        self.oids = Dictionary of { OID: value } from the response.
        self.failed = Dictionary of { OID: reason } for OIDs that were
                      marked as failed in the response (v2c/v3 only).
    """
    # This message is used by SNMPv3 USM to discover a foreign engineId.
    DISCOVERY_MESSAGE = SnmpMessage(
        [], version=3, pduType='get-request', errorStatus=0,
        errorIndex=0, flags=REPORT_FLAG, securityModel=3, maxSize=65535,
        contextEngineId=b'', contextName=b'', encoding='latin1')

    def __init__(self, host, oids, pduType='get-request', port=161, version=0,
                 community=None, maxSize=65535, securityModel=USM,
                 userName=None, authSecret=None, hashFunc=md5, privSecret=None,
                 cipher=DES, engineId=b'', contextName='', non_repeaters=0,
                 max_repetitions=1, retries=1, timeout=2.0, callback=None,
                 queue=None, max_pending=None, encoding='latin1'):
        # Validate parameters required to create SNMP message.
        self.version = version
        errorStatus = errorIndex = 0
        flags = REPORT_FLAG
        if pduType == 'get-bulk-request':
            # GetBulkRequests replace errorStatus and errorIndex.
            errorStatus = non_repeaters
            errorIndex = max_repetitions
        # Set SNMP v3 parameters to defaults.
        self.engineId = BYTES(engineId, 'latin1')
        self.userName = self.authSecret = self.privSecret = None
        self.hashFunc = self.cipher = None
        if self.version == 3:
            # If USM mode specified validate User Security Mode parameters.
            if securityModel == USM:
                # Set self.userName, authSecret, privSecret, and flags.
                if not userName:
                    raise ValueError("User Security Model requires userName")
                self.userName = BYTES(userName, encoding)
                if not callable(hashFunc):
                    raise ValueError("Invalid hash function. Try md5 or sha1")
                self.hashFunc = hashFunc
                if not hasattr(cipher, 'new'):
                    if cipher is None and AES is None and DES is None:
                        raise ValueError("Ciphers not available. "
                                         "pip install pycryptodomex")
                    raise ValueError("Invalid cipher: %s. Try asnmp.DES or "
                                     "asnmp.AES" % repr(cipher))
                self.cipher = cipher
                if authSecret:
                    self.authSecret = BYTES(authSecret, encoding)
                    flags |= AUTH_FLAG
                if privSecret:
                    self.privSecret = BYTES(privSecret, encoding)
                    flags |= PRIV_FLAG
            else:
                # Currently only ANY, SNMPv1, SNMPv2c, and USM are supported.
                if userName or authSecret or privSecret:
                    raise ValueError("Unknown security model %s" %
                                     repr(securityModel))
        # Create base message. Will be missing UsmSecurity parameters.
        self.message = SnmpMessage(
            oids, version=version, pduType=pduType, community=community,
            errorStatus=errorStatus, errorIndex=errorIndex, flags=flags,
            contextName=contextName, contextEngineId=engineId,
            securityModel=securityModel, maxSize=maxSize, encoding=encoding)
        self.request = self.message
        # Call UDP Operation base class constructor with its parameters.
        UdpOperation.__init__(self, host, port=port, retries=retries,
                              timeout=timeout, queue=queue, callback=callback,
                              max_pending=max_pending)
        # Create reply successful oids and failed oids dictionaries.
        self.requestOids = dict(oids)
        self.oids = {}
        self.failed = {}

    def get_datagram(self, engine_info=None):
        """Return the current request packet's datagram.

        SNMP v3 may require engine_info if engineId was not provided by
        the user or USM security model is being used.

        May raise ValueError if the encoding of the datagram fails.
        """
        self.request = self.message
        if self.version == 3:
            # If engineId was not provided was it provided by the dispatcher?
            if not self.engineId and engine_info:
                # Grab engineId from cached engine_info from dispatcher.
                self.engineId = engine_info.engineId
                self.message.contextEngineId = self.engineId
            # SNMP v3 operations *require* engineId.
            if not self.engineId:
                # We must perform discovery to get target host's engine ID.
                # print("No engine ID. Sending discovery message")
                self.request = self.DISCOVERY_MESSAGE
            elif self.message.securityModel == USM:
                # USM also requires timely engineBoots and engineTime.
                if not engine_info:
                    # Need to perform discovery for engineBoots/engineTime.
                    # print("No engine information. Sending discovery message")
                    self.request = self.DISCOVERY_MESSAGE
                else:
                    # Has the cached engine_info from the dispatcher expired?
                    time_window = USM_TIME_WINDOW - max(self.timeout, 10)
                    if abs(time.time() - engine_info.timestamp) > time_window:
                        # Need to perform discovery to update cache.
                        print("Need to refresh engine information")
                        self.request = self.DISCOVERY_MESSAGE
                    else:
                        # Within time window. Patch values into self.message.
                        self.message.usmSecurity = UsmSecurity(
                            engineId=self.engineId,
                            engineBoots=engine_info.engineBoots,
                            engineTime=engine_info.engineTime,
                            userName=self.userName, hmac=b'', salt=b'')
                        # Register credentials now, if they were provided.
                        if self.privSecret or self.authSecret:
                            print("Register credentials: user %r engineId=%r" %
                                  (self.userName, self.engineId))
                            add_credentials(self.engineId, self.userName,
                                            self.authSecret, self.privSecret,
                                            self.hashFunc, self.cipher)
        # Encode request into bytes and return.
        return self.request.get_datagram()

    def receive(self, reply):
        """Called by UdpThread when a reply received with matching ID.

        'reply' will be the message object.

        Should return True if this operation is done, or False if we
        need to send another packet and have reconfigured to do so.
        """
        # print("Got reply %s" % repr(reply))
        self.reply = reply
        if reply.get_error():
            # Error occurred. We're done.
            self.error = reply.get_error()
            return True
        elif self.request == self.DISCOVERY_MESSAGE:
            # SNMP v3 discovery reply. Did we get a valid engine ID?
            if reply.usmSecurity and reply.usmSecurity.engineId:
                # Engine ID was cached successfully! We're not done.
                return False
            else:
                self.error = "No engine ID in discovery response!"
                return True
        # Valid response. We're done.
        return True

    def handle_finish(self):
        """Create self.oids dictionary, and expand error message."""
        # print("handle_finish: self.reply=%s" % repr(self.reply))
        if self.reply:
            # Update our oids dictionary with the reply tuples (lose ordering).
            self.oids.update(self.reply.oids)
            # Set our failed dictionary to any failed OIDs.
            self.failed = self.reply.failed
            # Check and flag fatal errors in message.
            if self.error:
                # Try to expand out SNMP v1 error message.
                errorIndex = self.reply.errorIndex      # 1-based
                if errorIndex and errorIndex <= len(self.reply.varBindList):
                    oid = self.reply.varBindList[errorIndex - 1].get('name')
                    self.error += ' (%s)' % oid
                else:
                    self.error += ' (errorIndex %s)' % errorIndex
            elif self.reply.error:
                # errorStatus set. Only flag fatal errors.
                if self.reply.errorStatus not in (2,):
                    self.error = self.reply.error
                    self.ok = False
            elif len(self.oids) == 1:
                # Check for SNMP v3 engine OID errors.
                error_oid, error_value = next(iter(self.oids.items()))
                error_message = self.reply.ERROR_OIDS.get(error_oid)
                if error_message:
                    self.error = error_message
                    self.ok = False
#end class SNMPOperation(UdpOperation)


class UdpThread(threading.Thread):
    """Base class of a thread to perform UDP operations on hosts.

        UdpThread(iface='', debug=0, throttle=1000)

    'throttle' is the maximum number of packets to send per second.
               Defaults to 1000 which implies maximum transmit rate.
               Minimum value is effectively 100.
    'iface' is the interface to bind the UDP socket to. Leaving it blank
            binds to INADDR_ANY.
    """
    # Sleep times
    IDLE_SLEEP = 0.100      # Sleep thread 100ms when idle
    ACTIVE_SLEEP = 0.010    # Sleep thread 10ms when active.
    # Socket buffersize to set. Bigger=better.
    BUFFERSIZE = 131070
    # self.loglist maximum size (in messages).
    LOGSIZE = 255
    # Packet class to use when receiving packets. Must be overridden!
    Packet = None

    def __init__(self, **kwargs):
        # Grab keyword arguments.
        self.throttle = int(kwargs.pop('throttle', 1000))
        self.debug = int(kwargs.pop('debug', 0))
        self.iface = kwargs.pop('iface', '')
        if not self.Packet:
            raise RuntimeError("Cannot instantiate base class")
        # Call original constructor (will complain if extra kwargs present).
        threading.Thread.__init__(self, **kwargs)
        # Record parent thread (the one that creates this object).
        self.parent = threading.current_thread()
        # Initialize attributes
        self.status = "Stopped"             # Current thread status.
        self.endEvent = threading.Event()   # End event.
        self.queue = Queue.Queue()          # queue of Operation() objects.
        self.engines = {}                   # { IP: EngineInfo }
        self.logmutex = threading.Lock()    # Mutex for loglist.
        self.loglist = []                   # List of log messages.
        self.idle = True                    # All operations complete.
        self.active = 0                     # Number of active operations.
        self.ticks = 0
        # Create a configured socket.
        self.sock = self.get_socket(self.iface)

    def get_socket(self, iface):
        """Return a UDP socket configured for the specified interface.

        It will be bound to the specified interface, random port (0).
        Will try to increase the socket's buffer size to self.BUFFERSIZE
        to allow more packets to queue without dropping (when receiving)
        or blocking (when sending).
        Windows defaults to a puny buffersize of 8,192 bytes which is
        only about 50-90 SNMP packets at best.
        May raise socket.error if an operation fails.
        """
        # Create UDP socket.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Try to adjust send/receive buffer sizes (if necessary).
        try:
            for option in (socket.SO_RCVBUF, socket.SO_SNDBUF):
                buffer_size = sock.getsockopt(socket.SOL_SOCKET, option)
                if buffer_size < self.BUFFERSIZE:
                    sock.setsockopt(socket.SOL_SOCKET, option, self.BUFFERSIZE)
                    new_size = sock.getsockopt(socket.SOL_SOCKET, option)
                    self.log("Adjusted %s buffersize from %d to %d" %
                             ("RCV" if option == socket.SO_RCVBUF else "SND",
                              buffer_size, new_size))
        except socket.error:
            pass
        # Allow address reuse (courtesy) and put socket into non-blocking mode.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        # Bind to specified interface with random port (port=0).
        sock.bind((iface, 0))
        # Return configured socket
        return sock

    def run(self):
        """This is the method that executes in a separate thread.

        It pulls UdpOperation objects out of self.queue and tries to
        send their datagrams to their host over self.sock.
        Once sent successfully, the UdpOperation is added to the
        host_pending dictionary of the host in 'pending'.
            pending = { host: { request_id: UdpOperation } }

        Any datagrams received on self.sock are matched up with a host
        from 'pending' dictionary and decoded. If the request_id
        matches up with a previous operation the packet is processed and
        the UdpOperation is finished.
        """
        self.endEvent.clear()
        self.status = "Starting"
        self.log(self.status)
        pending = {}    # { host: { request_id: operation, ... }, ... }
        self.idle = False if self.queue.qsize() else True
        # Run main thread loop until signalled to exit.
        thread_error = ""
        while self.endEvent.is_set() is False:
            self.ticks += 1
            # 1) Try transmit and start all queued operations.
            count = 0
            reschedule = []
            while self.endEvent.is_set() is False:
                try:
                    operation = self.queue.get_nowait()
                except Queue.Empty:
                    break
                # Do we have too many ongoing operations to this host?
                (host, port) = operation.get_address()
                host_pending = pending.get(host, {})
                if len(host_pending) < operation.max_pending:
                    # Start the operation.
                    operation.start()
                    # Do we have engine_info stored for this IP?
                    engine_info = self.engines.get(operation.host)
                    # Attempt to encode the SNMP packet (<50ms).
                    try:
                        datagram = operation.get_datagram(engine_info)
                    except ValueError as err:
                        # Encode failed. Fail the operation (bad OIDs?)
                        traceback.print_exc()
                        operation.finish(error=str(err))
                        continue
                    try:
                        # Can block for a long time for fragmented packets.
                        num_sent = self.sock.sendto(datagram, (host, port))
                        if num_sent != len(datagram):
                            raise socket.error("Partial send %d/%d" %
                                               (num_sent, len(datagram)))
                    except socket.error as err:
                        if err.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                            # OS socket buffer full. Reschedule this operation.
                            self.log("Send buffer full, waiting")
                            reschedule.append(operation)
                            operation.pause()
                        else:
                            # Serious socket error. Log and fail the operation.
                            error = "Failed to send to %s: %s" % (host, err)
                            self.log(error)
                            operation.finish(error=error)
                            break
                    else:
                        # Sent successfully. Increase active operation count.
                        count += 1
                        # Add operation to pending list.
                        host_pending[operation.get_id()] = operation
                        # self.log("Adding operation to host %s" % host)
                        pending[host] = host_pending
                else:
                    # Too many operations to host. Reschedule the operation.
                    reschedule.append(operation)
                # Check our throttle limit
                if (count / self.ACTIVE_SLEEP) > self.throttle:
                    self.log("Throttling transmits - sent %d/%d" %
                             (count, self.queue.qsize() + count))
                    break

            # 2) Add rescheduled operations back into queue.
            for operation in reschedule:
                self.queue.put(operation)

            # 3) Receive and process any datagrams available on the UDP socket.
            while self.endEvent.is_set() is False:
                # Try to receive a packet.
                try:
                    datagram, (host, port) = self.sock.recvfrom(65535)
                except socket.error as err:
                    # No packet available. Break receive loop.
                    if err.errno in (errno.EAGAIN, errno.EWOULDBLOCK,
                                     errno.ECONNRESET, errno.ENETRESET):
                        # Ignore expected error messages.
                        # EAGAIN and EWOULDBLOCK are normal and means
                        #   that no packet available to receive.
                        # ECONNRESET is in response to an ICMP error from
                        #   a previously sent UDP packet.
                        # ENETRESET can be sent if the TTL expires.
                        pass
                    else:
                        # Real socket error occurred. End thread?
                        thread_error = "Socket receive error %s" % str(err)
                        # TODO: Maybe just log, and continue thread.
                        self.endEvent.set()
                    break
                # Got a packet. Are we expecting anything from this host?
                host_pending = pending.get(host, None)
                if not host_pending:
                    self.log("Unsolicited message from %s:%s ignored" %
                             (host, port))
                    continue
                # Try to decode the datagram into a self.Packet object.
                try:
                    packet = self.Packet(datagram=datagram)
                except (ValueError) as err:
                    self.log("Bad packet from %s:%s %s" % (host, port, err))
                    continue
                # For SNMPv3 messages cache engine_info into self.engines.
                if hasattr(packet, 'get_engine_info'):
                    self.engines[host] = packet.get_engine_info()
                # Is there an operation that expects this message?
                operation = host_pending.pop(packet.get_id(), None)
                if operation:
                    # Yes. Finish the operation.
                    # self.log("Got expected reply from %s:%s" % (host, port))
                    done = operation.receive(packet)
                    if done is True:
                        # Operation is done. Finish it.
                        operation.finish()
                    else:
                        # Operation needs to send more message. Reschedule it.
                        self.queue.put(operation)
                else:
                    # No. Unsolicited or too-late (timed out) packet. Ignore.
                    self.log("Unsolicited message ID %s from %s:%s ignored "
                             "(too late?)" % (packet.get_id(), host, port))

            # 4. Poll all pending operations (check for time-outs).
            num_pending = 0
            for host, host_pending in list(pending.items()):
                for ID, operation in list(host_pending.items()):
                    # Poll the operation. Is it still valid?
                    error = operation.poll()
                    if error:
                        # Failed or timed out. Remove from pending dictionary.
                        host_pending.pop(ID)
                        # Attempt to retry the operation.
                        if operation.retry() is True:
                            # Reschedule operation for another transmit.
                            # self.log("Retrying operation to %s" % host)
                            self.queue.put(operation)
                        else:
                            # Operation failed. Finish it with an error.
                            # self.log("Operation to %s failed: %s" % (host, error))
                            operation.finish(error=error)
                    else:
                        num_pending += 1
                # If host_pending is now empty, remove the host from pending.
                if not host_pending:
                    pending.pop(host, None)

            # 5. Set thread status and sleep thread.
            num_queued = self.queue.qsize()
            if num_queued + num_pending == 0:
                # Thread is idle. Sleep longer.
                self.status = "Idle - %s ticks" % format(self.ticks, ',')
                self.idle = True
                time.sleep(self.IDLE_SLEEP)
            else:
                # Thread is active. Sleep short amount of time.
                self.status = "%d queued, %d active" % (num_queued, num_pending)
                self.idle = False
                time.sleep(self.ACTIVE_SLEEP)
            # End thread loop if parent thread has ended.
            if self.parent.is_alive() is False:
                thread_error = "Parent thread died"
                break
        # Exited thread main loop. Close socket.
        self.sock.close()
        if thread_error:
            self.status = "Exited due to error: %s" % thread_error
        else:
            self.status = "Exited normally"
        # TODO: Cancel any remaining operations.
        self.log(self.status)

    def log(self, message):
        """Add message to loglist with timestamp, preventing duplicates.

        Must be thread-safe since this is called by child threads.
        """
        # Thread-safety for logs.
        unique = False
        timestamp = time.strftime("%a %I:%M%p - ")
        with self.logmutex:
            # Add log message if it not the same as the last one.
            if not self.loglist or not self.loglist[-1].endswith(message):
                unique = True
                self.loglist.append(timestamp + message)
            # Discard oldest log message if log size is too big.
            if len(self.loglist) > self.LOGSIZE:
                self.loglist.pop(0)
        # Print message (outside mutex!) if debugging is enabled.
        if unique is True and self.debug:
            print(message)

    def stop(self, block=False):
        """Signal thread to shutdown and optionally block until it does."""
        self.endEvent.set()
        if block is True:
            self.join()
#end class UdpThread(threading.Thread)


class GetBatchOperation(object):
    """Object to manage multiple gets to a host.

    Allows requesting many OIDs in many separate GetRequests and then
    consolidating all the replies to one place (self.oids).
    If a 'queue' was specified, OIDs from each reply are added to the
    queue as they are received.
    If a 'callback' function is specified it is called when all requests
    have completed.
    'max_pending' is the maximum number of operations to have ongoing to
                  this host. Defaults to 1.

    During the operation:
    self.elapsed is updated on each reply.
    self.progress (0-100%) is updated on each reply.

    Upon completion:
    self.finished will be True
    self.ok will be True if no errord occurred.
    self.error will contain the error message.
    self.errors is a list of individual operation failure messages.
    self.oids contains the { OID: value } from all replies.
    """
    def __init__(self, thread, agent, timeout=None, queue=None, callback=None):
        self.thread = thread
        self.host = agent
        self.timeout = timeout
        self.pending = []
        self.error = ''
        self.errors = []
        self.oids = {}
        self.finished = False
        self.ok = False
        self.queue = queue
        self.callback = callback
        self.max_pending = 1
        self.active = []
        self.total = 0
        # Attributes to mimick UdpOperation.
        self.started = False
        self.timestamp = False
        self.progress = 0
        self.elapsed = 0

    def start(self):
        """Start the GetBatchOperation."""
        # First send, mark start time.
        self.started = time.time()
        self.timestamp = self.started
        # Calculate timeout by totalling all pending requests.
        total = sum(kwargs.get('timeout', 4.0) for kwargs in self.pending)
        self.timeout = 1 + total
        # Calculate total operations in this GetBatchOperation.
        self.total = len(self.pending)
        self.send_next()

    def send_next(self):
        """Schedule the next operations. Must be thread-safe."""
        # Send requests so that less than self.max_pending are in-flight.
        while self.pending and len(self.active) < self.max_pending:
            # Schedule next pending request with thread (list.pop() is atomic).
            kwargs = self.pending.pop(0)
            self.active.append(self.thread.getMany(
                block=False, callback=self.cb_func, **kwargs))

    def cb_func(self, operation):
        """Callback function. Executed in the thread. Must be thread-safe."""
        self.active.remove(operation)
        # This callback could occur after operation failed (pending cleared).
        if self.finished is True:
            return
        # Update successful OIDs.
        self.oids.update(operation.oids)
        # Add OIDs to the queue, if one was specified.
        if self.queue:
            self.queue.put(operation.oids)
        # If an error occurred, add it to self.errors.
        if operation.ok is False:
            self.errors.append(operation.error)
        # Update progress and elapsed.
        remaining = len(self.pending) + len(self.active)
        self.progress = min(100 - int(round(remaining * 100.0 / self.total)), 99)
        elapsed = abs(time.time() - self.started)
        self.elapsed = elapsed
        # Are all operation finished or did we time out?
        if (not self.pending and not self.active) or elapsed > self.timeout:
            # Operation finished. Set error message.
            error = ''
            if self.elapsed > self.timeout:
                error = "GetMany timed out %.1f sec" % self.timeout
            elif self.errors:
                error = "GetMany %d errors" % len(self.errors)
            self.finish(error=error)
        elif self.pending:
            # Try to schedule more operations.
            self.send_next()

    def finish(self, error=''):
        """Finish the operation."""
        self.error = error
        self.ok = True if not error else False
        self.finished = True
        self.progress = 100
        if callable(self.callback):
            self.callback(self)

    def cancel(self):
        """Cancel the operation. Will fail with "Cancelled" error message."""
        self.finish(error="Cancelled")

    def add(self, agent, oids, community='public', retries=1, timeout=4.0,
            max_pending=1):
        """Add an operation to the GetBatchOperation."""
        kwargs = {'agent': agent, 'oids': oids, 'community': community,
                  'retries': int(retries), 'timeout': float(timeout),
                  'max_pending': int(max_pending)}
        self.pending.append(kwargs)
        self.max_pending = max(self.max_pending, max_pending)

    def wait(self):
        """Wait for all operations to finish."""
        # Wait for finish or timeout.
        while not self.finished:
            time.sleep(0.1)
            if abs(time.time() - self.started) > (self.timeout + 1):
                # Should never happen unless thread stalls.
                self.finished = True
                self.ok = False
                self.error = "GetMany stalled %.1f sec" % self.timeout
        # Operation done.
        if self.pending:
            # TODO: Clean up self.pending into self.errors?
            self.pending = []
#end class GetBatchOperation(object)


class InstOperation(object):
    """Object to manage gets of OIDs with instances to a host.

    Allows requesting several OID templates, each of which are percent
    formatted with every instance before being requested. This is far
    more CPU-friendly and memory efficient than regular GetMany class.

    'templates' is a dictionary of OID templates and their names:
        { '1.3.6.1.2.1.1.9.1.2.%s': 'sysORID',
          '1.3.6.1.2.1.1.9.1.3.%s': 'sysORDescr',
          '1.3.6.1.2.1.1.9.1.4.%s': 'sysORUpTime', }
    'instances' is a list of values to % format each OID with. eg:
        [ 1, 2, 3, 4, 5, 6 ] or even: range(1,7)

    In the example above, all three OIDs will be requested with each
    instance number resulting in a total of 18 OID requests. The results
    will be added to the queue as 2-tuples of ( instance, {key: value} )
    One such 2-tuple for instance 1 could return the following:
        ( 1, {'sysORID': '1.3.6.1.6.3.1', 'sysORUpTime': 0,
              'sysORDescr': 'The MIB module for SNMPv2 entities'} )

    Multiple formatting is possible by using tuples for instances:
        template = '1.3.6.1.2.1.1.9.1.%s.%s'
        instance = [(1,1), (1,2), (1,3), ...]

    The total number of requests sent out are:
        len(templates) * len(instances)
    This can be quite a large number of OIDs so the request is broken up
    into multiple GET operations. The 'max_oids' argument specified the
    maximum number of OIDs to put into a single message. This defaults
    to 55 which is just small enough to fit in a single Ethernet frame.
    This number may have to be reduced if OIDs are very long.
    The OIDs sent per packet is: max_oids // len(templates)
    This means the number of templates cannot be higher than max_oids.

    During the operation:
    self.packing = Number of instances sent per SNMP GET messages.
    self.elapsed is updated on each reply.
    self.progress (0-100%) is updated on each reply.
    self.queue is the Queue.Queue() that contains the received replies.

    Upon completion:
    self.finished will be True
    self.ok will be True if no errord occurred.
    self.error will contain the error message.
    self.errors is a list of individual operation failure messages.
    """
    def __init__(self, thread, agent, templates, instances, queue=None,
                 max_oids=55, community='public', op_retries=1, timeout=None,
                 op_timeout=2.0, max_pending=1, callback=None):
        self.thread = thread
        self.host = agent
        self.templates = templates
        self.instances = instances
        self.callback = callback
        self.queue = Queue.Queue() if queue is None else queue
        self.community = community
        self.op_retries = int(op_retries)
        self.op_timeout = float(op_timeout)
        self.max_pending = int(max_pending)
        # Calculate packing of instances into single messages.
        if len(templates) > max_oids:
            raise ValueError("max_oids of %s too small for %s OID templates." %
                             (max_oids, len(templates)))
        self.packing = max(1, int(max_oids) // len(templates))
        num_ops = (len(instances) + self.packing - 1) // self.packing
        # If timeout not specified, calculate it from number of operations.
        if timeout is None:
            self.timeout = (num_ops * self.op_timeout) + 1
        else:
            self.timeout = float(timeout)
        # Set instance attributes.
        self.ok = False
        self.finished = False
        self.error = ''
        self.errors = []
        self.progress = 0
        self.elapsed = 0
        self.active = []
        self.pending = {}
        self.current = 0
        # Immediately start the operation.
        self.started = time.time()
        self.timestamp = self.started
        self.send_next()

    def send_next(self):
        """Schedule the next operations. Must be thread-safe."""
        # Schedule operations if we are under max_pending and are not finished.
        while (len(self.active) < self.max_pending and
               self.current < len(self.instances)):
            # Grab next set of instances and format OIDs with them.
            end = min(self.current + self.packing, len(self.instances))
            instances = (self.instances[i] for i in range(self.current, end))
            pending = {}
            for inst in instances:
                for (oid, key) in self.templates.items():
                    try:
                        pending[oid % inst] = (inst, key)
                    except TypeError:
                        # Failed to format an OID. Stop the operation.
                        error = "Failed to format %r with %r" % (oid, inst)
                        self.finish(error)
                        return
            # Update our pending dictionary (atomic, thread-safe).
            self.pending.update(pending)
            # Schedule a GET request and add to active operations list.
            self.active.append(self.thread.getMany(
                self.host, pending, community=self.community, block=False,
                retries=self.op_retries, timeout=self.op_timeout,
                callback=self.cb_func, max_pending=self.max_pending))
            self.current = end

    def cb_func(self, operation):
        """Callback function. Executed in the thread. Must be thread-safe."""
        self.active.remove(operation)
        # This callback could occur after operation failed (pending cleared).
        if self.finished is True:
            return
        # Process reply OIDs by removing the instance/key from self.pending.
        results = {}
        for oid, value in operation.oids.items():
            instance, key = self.pending.pop(oid, (None, None))
            values = results.setdefault(instance, {})
            values[key] = value
        # Add each instance to the queue.
        for instance, values in results.items():
            self.queue.put((instance, values))
        # If an error occurred, add it to self.errors.
        if operation.ok is False:
            self.errors.append(operation.error)
        # Update progress and elapsed.
        self.progress = min(int(round((self.current + len(self.active)) * 100.0 /
                                      max(1, len(self.instances)))), 99)
        self.elapsed = abs(time.time() - self.started)
        # Are we finished?
        if self.current >= len(self.instances) and not self.active:
            # All instances sent, and no more active operations.
            self.finish()
        elif self.elapsed > self.timeout:
            # We timed out.
            self.finish(error="InstGet timed out %.1f sec" % self.timeout)
        else:
            # Try to send more requests.
            self.send_next()

    def finish(self, error=''):
        """Finish the operation with or without an error."""
        # print("finish(%r) active=%s, pending=%s" % (error, len(self.active), len(self.pending)))
        self.ok = True if not error else False
        self.error = error if error else self.error
        if self.errors:
            self.ok = False
            self.error = "InstGet %d bad requests" % len(self.errors)
        self.finished = True
        self.progress = 100
        if callable(self.callback):
            self.callback(self)

    def cancel(self):
        """Cancel the operation. Will fail with "Cancelled" error message."""
        self.finish(error="Cancelled")

    def wait(self):
        """Wait for all operations to finish."""
        # Wait for finish or timeout.
        while not self.finished:
            time.sleep(0.1)
            if abs(time.time() - self.started) > (self.timeout + 1):
                # Should never happen unless thread stalls.
                self.finished = True
                self.ok = False
                self.error = "InstGet stalled %.1f sec" % self.timeout
        # Operation done.
        if self.pending:
            # TODO: Clean up self.pending into self.errors?
            self.pending = []
#end class InstOperation(object)


class WalkOperation(object):
    """Object to manage walking an OID tree in an Agent.

    A base OID is specified and then walked using GetNext or GetBulk
    requests. This operation keeps issuing these requests until either
    max_results is reached, or the baseOID of the replies changes.

    'base_oid' is the OID to start the walk with.
    'max_results' will stop the walk when the number of results reaches
                  this number. Defaults to None to keep going until the
                  base OID changes.
    'bulk' defaults to False to use single GetNext requests. If set to
           True it will use SNMPv2c GetBulk requests.
    'max_repetitions' is used for SNMPv2C GetBulk requests only.
    'timeout' defaults to 10.0 seconds. Large walks may take longer.

    During the operation:
    self.elapsed is updated on each reply.
    self.queue is the Queue.Queue() that contains the received replies.

    Upon completion:
    self.finished will be True
    self.ok will be True if no errord occurred.
    self.error will contain the error message.
    self.errors is a list of individual operation failure messages.
    """
    def __init__(self, thread, agent, base_oid, queue=None, max_results=None,
                 community='public', version=0, bulk=False, max_repetitions=1,
                 timeout=10.0, op_retries=1, op_timeout=2.0, callback=None):
        self.thread = thread
        self.host = agent
        self.base_oid = base_oid
        self.max_results = max_results
        self.max_repetitions = int(max_repetitions)
        self.community = community
        self.version = int(version)
        self.bulk = bool(bulk)
        self.timeout = float(timeout)
        self.queue = Queue.Queue() if queue is None else queue
        self.op_retries = int(op_retries)
        self.op_timeout = float(op_timeout)
        self.callback = callback
        # Set instance attributes.
        self.ok = False
        self.finished = False
        self.error = ''
        self.errors = []
        self.elapsed = 0
        self.count = 0
        # Immediately start the operation.
        self.started = time.time()          # Time the operation was started.
        self.timestamp = self.started       # Same as self.started.
        self.operation = None
        self.send_next(base_oid)

    def send_next(self, last_oid):
        """Schedule the next operation. Must be thread-safe."""
        if self.bulk is True:
            # print("GetBulk(%s)" % last_oid)
            op = self.thread.getBulk(
                self.host, [last_oid], community=self.community,
                retries=self.op_retries, timeout=self.op_timeout, block=False,
                max_repetitions=self.max_repetitions, callback=self.cb_func)
        else:
            # print("GetNext(%s)" % last_oid)
            op = self.thread.getNext(
                self.host, last_oid, community=self.community,
                retries=self.op_retries, timeout=self.op_timeout, block=False,
                callback=self.cb_func)
        self.operation = op

    def cb_func(self, operation):
        """Callback function. Executed in the thread. Must be thread-safe."""
        # This callback could occur after operation failed/timed-out.
        if self.finished is True:
            return
        # Process reply OIDs.
        last_oid = None
        error = ''
        base_len = len(self.base_oid)
        if self.operation.reply:
            # print("Callback: %s results" % len(self.operation.reply.oids))
            for (oid, value) in self.operation.reply.oids:
                if oid[:base_len] == self.base_oid:
                    # Add to result queue, stripping off base_oid.
                    indices = tuple(
                        int(suboid) for suboid in oid[base_len:].split('.')
                        if suboid and suboid.isdigit())
                    if indices:
                        self.queue.put((indices, value))
                        self.count += 1
                        last_oid = oid
                    else:
                        # Bad OID reply. No indices after base_oid.
                        error = "unexpected oid: %r (%r)" % (oid, indices)
                        last_oid = None
                        break
                else:
                    # Base OID of reply changed! Stop walk.
                    last_oid = None
                    break
        # If an error occurred, add it to self.errors.
        if operation.ok is False:
            self.errors.append(operation.error)
        # Update elapsed.
        self.elapsed = abs(time.time() - self.started)
        # Are we finished?
        if last_oid is None or (self.max_results and
                                self.count >= self.max_results):
            # Walk of OID branch finished, or error occurred.
            self.finish(error)
        elif self.elapsed > self.timeout:
            # We timed out.
            self.finish(error="Walk timed out %.1f sec" % self.timeout)
        else:
            # Continue the walk, specifying the last OID retrieved.
            self.send_next(last_oid)

    def finish(self, error=''):
        """Finish the operation with or without an error."""
        if self.errors:
            self.ok = False
            reason = ("Walk %d bad requests: %s" %
                      (len(self.errors), ', '.join(self.errors)))
            error = ', '.join((error, reason)) if error else reason
        self.error = error
        self.ok = True if not self.error else False
        self.finished = True
        if callable(self.callback):
            self.callback(self)

    def cancel(self):
        """Cancel the operation. Will fail with "Cancelled" error message."""
        self.finish(error="Cancelled")

    def wait(self):
        """Wait for all operations to finish."""
        # Wait for finish or timeout.
        while not self.finished:
            time.sleep(0.1)
            if abs(time.time() - self.started) > (self.timeout + 1):
                # Should never happen unless thread stalls.
                self.finished = True
                self.ok = False
                self.error = "Walk stalled %.1f sec" % self.timeout
        # Operation done.
        if self.operation:
            self.operation = None
#end class WalkOperation(object)


class LLDPOperation(object):
    """Object to manage an LLDP sweep of a host.

    Will perform the necessary GET requests for the LLDP OIDs and walk
    the LLDP tables in order to extract all LLDP information.

    During the operation:
    self.elapsed is updated on each reply.
    self.progress (0-100%) is updated on each reply.

    Upon completion:
    self.finished will be True
    self.ok will be True if no error occurred.
    self.error will contain the error message if self.ok is False.
    self.errors is a list of individual operation failure messages.
    self.data contains the LLDP data for this host as a dictionary:
        { port: port_data, 'local': management_data }
    port_data is a dictionary with keys:
        RemChassisIdSubtype, RemChassisId, RemPortIdSubtype, RemPortId,
        RemPortDesc, RemSysName, RemSysDesc, 'remote'
    The 'local' and 'remote' keys contain management dictionaries:
        management_data = { IP: remote_data }
    Where remote_data is a dictionary with the following keys:
        ManAddrLen, ManAddrIfSubtype, ManAddrIfId, ManAddrOID
    """
    TABLES = (  # 3-tuples of (OID, name, max_repetitions)
        ("1.0.8802.1.1.2.1.3.7.1.2", 'LocPortIdSubtype', 70),   # Integer (3)
        ("1.0.8802.1.1.2.1.3.7.1.3", 'LocPortId', 50),      # MAC Address
        ("1.0.8802.1.1.2.1.3.7.1.4", 'LocPortDesc', 40),    # String iface name
        ("1.0.8802.1.1.2.1.3.8.1", 'LocManAddrTable', 40),  # int,int,int,OID
        ("1.0.8802.1.1.2.1.4.1.1.4", 'RemChassisIdSubtype', 70),  # Integer (4)
        ("1.0.8802.1.1.2.1.4.1.1.5", 'RemChassisId', 50),   # MAC Address
        ("1.0.8802.1.1.2.1.4.1.1.6", 'RemPortIdSubtype', 70),  # Integer (3)
        ("1.0.8802.1.1.2.1.4.1.1.7", 'RemPortId', 40),      # MAC Address
        ("1.0.8802.1.1.2.1.4.1.1.8", 'RemPortDesc', 40),    # String iface name
        ("1.0.8802.1.1.2.1.4.1.1.9", 'RemSysName', 40),     # String ('570IPG')
        ("1.0.8802.1.1.2.1.4.1.1.10", 'RemSysDesc', 20),    # String (long)
        # ("1.0.8802.1.1.2.1.4.1.1.11",'RemSysCapSupported', 40), # Useless
        # ("1.0.8802.1.1.2.1.4.1.1.12",'RemSysCapEnabled', 40),   # Useless
        ("1.0.8802.1.1.2.1.4.2.1", 'RemManAddrTable', 40),  # int,int,OID
    )
    LOC_NAMES = {3: 'ManAddrLen', 4: 'ManAddrIfSubtype',
                 5: 'ManAddrIfId', 6: 'ManAddrOID'}
    REM_NAMES = {3: 'ManAddrIfSubtype', 4: 'ManAddrIfId',
                 5: 'ManAddrOID'}

    def __init__(self, thread, agent, community='public', bulk=True,
                 op_retries=1, timeout=30, op_timeout=2.0, callback=None):
        self.thread = thread
        self.host = agent
        self.queue = Queue.Queue()
        self.callback = callback
        self.community = community
        self.bulk = bool(bulk)
        self.op_retries = int(op_retries)
        self.op_timeout = float(op_timeout)
        self.timeout = float(timeout)
        # Set instance attributes.
        self.ok = False
        self.finished = False
        self.error = ''
        self.errors = []
        self.progress = 0
        self.elapsed = 0
        self.current = 0
        self.operation = None
        self.data = {}
        # Immediately start the LLDP scan.
        self.started = time.time()          # Time the operation was started.
        self.timestamp = self.started       # Same as self.started.
        self.send_next()

    def send_next(self):
        """Schedule walk operation on the next table. Must be thread-safe."""
        if self.current < len(self.TABLES):
            # Schedule the next walk operation.
            OID, name, reps = self.TABLES[self.current]
            self.operation = self.thread.walk(
                self.host, OID, queue=self.queue, community=self.community,
                bulk=self.bulk, max_repetitions=reps, block=False,
                op_retries=self.op_retries, timeout=self.timeout,
                op_timeout=self.op_timeout, callback=self.cb_func)
        else:
            # Finished.
            self.operation = None

    def cb_func(self, operation):
        """Callback function. Executed in the thread. Must be thread-safe."""
        # This callback could occur after operation failed (pending cleared).
        self.operation = None
        if self.finished is True or self.current >= len(self.TABLES):
            return
        # Process reply OIDs depending on type.
        OID, name, reps = self.TABLES[self.current]
        print("%s - %s - %s - Got %s in queue" % (OID, name, reps, operation.queue.qsize()))
        self.current += 1
        while operation.queue.qsize():
            prefix, value = operation.queue.get()
            if not prefix:
                continue
            if name in ('LocPortIdSubtype', 'LocPortId', 'LocPortDesc'):
                # Prefix is a 1-based port number. Convert to 0-based.
                portnum = prefix[0] - 1
                port_data = self.data.setdefault(portnum, {})
                if name == 'LocPortId':
                    if port_data.get('LocPortIdSubtype') == 3:
                        # Convert MAC address to string.
                        value = ':'.join('%02x' % ord(char) for char in value)
                port_data[name] = value
            elif name == 'LocManAddrTable' and len(prefix) > 2:
                # Prefix is (instance, addrFamily, address).
                addrFamily = prefix[1]
                item = self.LOC_NAMES.get(prefix[0], 'Unknown(%s)' % prefix[0])
                IP = parse_address(addrFamily, prefix[2:])
                local_data = self.data.setdefault('local', {})
                management = local_data.setdefault(IP, {})
                management[item] = value
            elif name == 'RemManAddrTable' and len(prefix) > 4:
                # Prefix is (inst, timeMark, portNum, index, addrFam, address).
                portnum = prefix[2] - 1
                port_data = self.data.setdefault(portnum, {})
                addrFamily = prefix[4]
                item = self.REM_NAMES.get(prefix[0], 'Unknown(%s)' % prefix[0])
                IP = parse_address(addrFamily, prefix[5:])
                remote_data = port_data.setdefault('remote', {})
                management = remote_data.setdefault(IP, {})
                management[item] = value
            elif len(prefix) > 1:
                # RemTable Prefix is (timeMark, portNum, index).
                portnum = prefix[1] - 1
                port_data = self.data.setdefault(portnum, {})
                if name == 'RemChassisId':
                    if port_data.get('RemChassisIdSubtype') == 4:
                        # Convert MAC address to string.
                        value = ':'.join('%02x' % ord(char) for char in value)
                if name == 'RemPortId':
                    if port_data.get('RemPortIdSubtype') == 3:
                        # Convert MAC address to string.
                        value = ':'.join('%02x' % ord(char) for char in value)
                port_data[name] = value
            else:
                # Invalid prefix. Ignore.
                continue
        # If an error occurred, add it to self.errors.
        if operation.ok is False:
            self.errors.append(operation.error)
        # Update progress and elapsed.
        self.progress = min(int(self.current * 100.0 / len(self.TABLES) + 0.5), 99)
        self.elapsed = abs(time.time() - self.started)
        # Are we finished?
        if self.current >= len(self.TABLES):
            # All tables walked. Finish with no error.
            self.finish()
        elif self.elapsed > self.timeout:
            # We timed out.
            self.finish(error="LLDPOperation timeout %.1f sec" % self.timeout)
        else:
            # Try to start the next walk.
            self.send_next()

    def finish(self, error=''):
        """Finish the operation with or without an error."""
        self.ok = True if not error else False
        if self.errors:
            self.ok = False
            self.error = "LLDPOperation %d bad requests" % len(self.errors)
        self.finished = True
        self.progress = 100
        if callable(self.callback):
            self.callback(self)

    def cancel(self):
        """Cancel the operation. Will fail with "Cancelled" error message."""
        self.finish(error="Cancelled")

    def wait(self):
        """Wait for all operations to finish."""
        # Wait for finish or timeout.
        while not self.finished:
            time.sleep(0.1)
            if abs(time.time() - self.started) > (self.timeout + 1):
                # Should never happen unless thread stalls.
                self.finished = True
                self.ok = False
                self.error = "LLDPOperation stalled %.1f sec" % self.timeout
        # Operation done.
        if self.operation:
            # TODO: Clean up self.operation into self.errors?
            self.operation = None
#end class LLDPOperation(object)


class SnmpThread(UdpThread):
    # Override packet UdpThread uses when decoding received datagram.
    Packet = SnmpMessage

    def get(self, agent, oid, community='public', version=0, securityModel=USM,
            userName=None, authSecret=None, hashFunc=md5, privSecret=None,
            cipher=DES, engineId=b'', contextName='', retries=1, timeout=2.0,
            queue=None, callback=None, block=True):
        """Schedule a GET operation for the given OID on the agent.

        May raise ValueError on an invalid OID, retries, or timeout value.
        Returns an SNMPOperation() object.
        """
        # Wrap into tuple if it is a simple OID, otherwise pass it.
        if isinstance(oid, str) or isinstance(oid, TEXT_TYPES):
            oid = (oid,)
        # Simple wrapper for get_many
        operation = self.getMany(
            agent, oid, community=community, version=version,
            securityModel=securityModel, userName=userName, cipher=cipher,
            authSecret=authSecret, hashFunc=hashFunc, privSecret=privSecret,
            engineId=engineId, contextName=contextName, retries=retries,
            timeout=timeout, queue=queue, callback=callback, block=block)
        return operation

    def getMany(self, agent, oids, community='public', version=0,
                securityModel=USM, userName=None, authSecret=None,
                hashFunc=md5, privSecret=None, cipher=DES, engineId=b'',
                contextName='', retries=1, timeout=2.0, queue=None,
                callback=None, max_pending=1, maxSize=65535, block=True):
        """Schedule a single GET operation for the sequence of oids.

        'oids' must be a sequence of OID values to fetch, but for memory
               efficiency can also be a generator object.

        Note: It is recommended not to request more than 1024 OIDs per
              GetRequest. This will usually block the thread then fail
              at the socket layer when the packet is fragmented.
        May raise ValueError on an invalid OID, retries, or timeout value.
        Returns an SNMPOperation() object on success.
        """
        if not self.is_alive():
            raise RuntimeError("Cannot perform GET - Thread not running")
        if isinstance(oids, str) or isinstance(oids, TEXT_TYPES):
            raise ValueError("oids must be a sequence not %s" % type(oids))
        if block is True:
            queue = Queue.Queue()
            callback = None
        # Generate 2-tuple list from 'oids', setting value to None.
        oids = [(oid, None) for oid in oids]
        # Instantiate an SNMP Operation for this message.
        operation = SNMPOperation(
            agent, oids, pduType='get-request', community=community,
            version=version, maxSize=maxSize, securityModel=securityModel,
            userName=userName, cipher=cipher, authSecret=authSecret,
            hashFunc=hashFunc, privSecret=privSecret, engineId=engineId,
            contextName=contextName, retries=retries, timeout=timeout,
            queue=queue, callback=callback, max_pending=max_pending)
        # Queue up operation into thread's workqueue.
        self.queue.put(operation)
        if block is True:
            try:
                queue.get(block=True, timeout=timeout * (retries + 1) + 1.0)
            except Queue.Empty:
                # Something went bad here. Maybe thread stopped.
                pass
        return operation

    def getNext(self, agent, oid, community='public', retries=1, timeout=2.0,
                queue=None, callback=None, max_pending=1, block=True):
        """Schedule a single GetNext operation for the given oid.

        May raise ValueError on an invalid OID, retries, or timeout value.
        Returns an SNMPOperation() object.
        """
        if not self.is_alive():
            raise RuntimeError("Cannot perform GetNext - Thread not running")
        if block is True:
            queue = Queue.Queue()
            callback = None
        # Instantiate an Operation for this message.
        operation = SNMPOperation(agent, [(oid, None)], community=community,
                                  pduType='get-next-request', retries=retries,
                                  timeout=timeout, queue=queue,
                                  max_pending=max_pending, callback=callback)
        # Queue up operation to be sent and return it.
        self.queue.put(operation)
        if block is True:
            try:
                queue.get(block=True, timeout=timeout * (retries + 1) + 1.0)
            except Queue.Empty:
                # Something went bad here. Maybe thread stopped.
                pass
        return operation

    def getBulk(self, agent, oids, community='public', retries=1, timeout=2.0,
                non_repeaters=0, max_repetitions=1, queue=None, callback=None,
                max_pending=1, block=True):
        """Schedule a single SNMPv2c GetBulk request for the given oids.

        'oids' must be a list of OID values to fetch, but for memory
               efficiency can also be a generator object.
        'non_repeaters' the first X number of OIDs will be walked only
                        once and return a single result in the response.
                        This defaults to zero to disable this behavior.
        'max_repetitions' the remainder of the OIDs will be walked this
                          many times, each one producing this many
                          results in the response.

        Raises ValueError on an invalid OID, retries, or timeout value.
        Returns an SNMPOperation() object.
        """
        if not self.is_alive():
            raise RuntimeError("Cannot perform GetBulk - Thread not running")
        if isinstance(oids, str) or isinstance(oids, TEXT_TYPES):
            raise ValueError("oids must be a sequence not %s" % type(oids))
        if block is True:
            queue = Queue.Queue()
            callback = None
        # Generate 2-tuple list from 'oids', setting value to None.
        oids = [(oid, None) for oid in oids]
        # Instantiate an SNMPv2c Operation for this message.
        operation = SNMPOperation(agent, oids, community=community,
                                  pduType='get-bulk-request', version=1,
                                  non_repeaters=non_repeaters, retries=retries,
                                  max_repetitions=max_repetitions, queue=queue,
                                  timeout=timeout, max_pending=max_pending,
                                  callback=callback)
        # Queue up operation to be sent and return it.
        self.queue.put(operation)
        if block is True:
            try:
                queue.get(block=True, timeout=timeout * (retries + 1) + 1.0)
            except Queue.Empty:
                # Something went bad here. Maybe thread stopped.
                pass
        return operation

    def set(self, agent, varBinds, community='private', version=0,
            securityModel=USM, userName=None, authSecret=None, hashFunc=md5,
            privSecret=None, cipher=DES, engineId=b'', contextName='',
            retries=1, queue=None, timeout=2.0, callback=None, max_pending=1,
            maxSize=65535, block=True):
        """Schedule a SET operation for the given list of OIDs and values.

        varBinds must be a list of (OID, value) tuples.
        May raise ValueError if and invalid OID, retries, or timeout
        value is supplies or an un-convertable value type is given.
        """
        if not self.is_alive():
            raise RuntimeError("Cannot perform SET - Thread not running")
        # Copy varbinds and ensure it is correct format (sequence of tuples).
        varBinds = [(oid, value) for oid, value in varBinds]
        if not varBinds:
            raise ValueError("varBinds must be a sequence of (OID, value)")
        if block is True:
            queue = Queue.Queue()
            callback = None
        # Instantiate an SNMP Operation for this message.
        operation = SNMPOperation(
            agent, varBinds, pduType='set-request', community=community,
            version=version, maxSize=maxSize, securityModel=securityModel,
            userName=userName, cipher=cipher, authSecret=authSecret,
            hashFunc=hashFunc, privSecret=privSecret, engineId=engineId,
            contextName=contextName, retries=retries, timeout=timeout,
            queue=queue, callback=callback, max_pending=max_pending)
        # Queue up operation to be sent and return it.
        self.queue.put(operation)
        if block is True:
            try:
                queue.get(block=True, timeout=timeout * (retries + 1) + 1.0)
            except Queue.Empty:
                # Something went bad here. Maybe thread stopped.
                pass
        return operation

    def batchGet(self, agent, requests, community='public', op_retries=1,
                 timeout=None, op_timeout=2.0, queue=None, callback=None,
                 block=True, max_pending=1):
        """Schedule multiple GETs and return a GetBatchOperation()

        'requests' should be a list of operations, each one a list of
        OIDs to fetch (or single OIDs). Example:
            [ [oid, oid, oid, ...], oid, [oid], [oid, oid, ...], ... ]

        Each operation is mapped to a single GetRequest. A generator
        can be passed instead of a list for memory efficiency.

        Note: It is not recommended to have more than 1024 OIDs in a
              single GetRequest message. This will usually block while
              sending as it fragments, then fail at the socket layer.

        'max_pending' is the maximum number of operations to have
        ongoing to this host. Defaults to 1.

        If timeout is `None`, it will wait until all operations have
        competed each with their own op_timeout and op_retries.

        Returns a GetBatchOperation() object which will consolidate all
        the reply oids into one dictionary (operation.oids).
        """
        if not self.is_alive():
            raise RuntimeError("Cannot perform batchGet - Thread not running")
        if isinstance(requests, str) or isinstance(requests, TEXT_TYPES):
            raise ValueError("requests must be a list not %s" % type(requests))
        # Create and configure GetBatchOperation object.
        operation = GetBatchOperation(self, agent, timeout, queue, callback)
        for oids in requests:
            if '.' in oids:
                # Single OID in this operation.
                oids = (oids,)
            # Create SNMP operation and add to GetBatchOperation object.
            operation.add(agent, oids, community=community,
                          retries=op_retries, timeout=op_timeout,
                          max_pending=max_pending)
        # Start the GetBatchOperation.
        operation.start()
        if block is True:
            operation.wait()
        return operation
    # To be backwards compatible with programs that use the old API name.
    bulkGet = batchGet

    def instGet(self, agent, templates, instances, queue=None, max_oids=55,
                community='public', timeout=None, op_retries=1, op_timeout=2.0,
                max_pending=1, callback=None, block=True):
        """Do multiple GETs of OID templates using several instances.

        Allows requesting OID templates, each of which are percent-
        formatted with every instance before being requested.
        This uses less CPU and memory than regular bulk gets.

        'templates' is a dictionary of OID templates and their names:
            { '1.3.6.1.2.1.1.9.1.2.%s': 'sysORID',
              '1.3.6.1.2.1.1.9.1.3.%s': 'sysORDescr',
              '1.3.6.1.2.1.1.9.1.4.%s': 'sysORUpTime', }
        'instances' is a list of values to % format each OID with. eg:
            [ 1, 2, 3, 4, 5, 6 ] or even: range(1,7)

        If timeout is `None`, it will wait until all operations have
        competed each with their own op_timeout and op_retries.

        Returns an InstOperation() object which will update its queue
        attribute with each reply.
        """
        if not self.is_alive():
            raise RuntimeError("Cannot perform instGet - Thread not running")
        # Create and start the InstOperation.
        operation = InstOperation(self, agent, templates, instances,
                                  queue=queue, max_oids=max_oids,
                                  community=community, op_retries=op_retries,
                                  timeout=timeout, op_timeout=op_timeout,
                                  max_pending=max_pending, callback=callback)
        if block is True:
            operation.wait()
        return operation

    def walk(self, agent, base_oid, queue=None, max_results=None,
             community='public', version=0, bulk=False, max_repetitions=1,
             timeout=10.0, op_retries=1, op_timeout=2.0, callback=None,
             block=True):
        """Perform a walk of the base_oid on the specified agent.

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

        Returns an InstOperation() object.
        """
        if not self.is_alive():
            raise RuntimeError("Cannot perform walk - Thread not running")
        # Create and start the WalkOperation.
        operation = WalkOperation(self, agent, base_oid, queue=queue,
                                  max_results=max_results, version=version,
                                  community=community, op_retries=op_retries,
                                  timeout=timeout, op_timeout=op_timeout,
                                  max_repetitions=max_repetitions, bulk=bulk,
                                  callback=callback)
        if block is True:
            operation.wait()
        return operation

    def get_lldp(self, agent, community='public', bulk=True, op_retries=1,
                 timeout=30, op_timeout=2.0, callback=None, block=True):
        """Return an LLDPOperation() object that collects LLDP data.

        If 'bulk' is True, it will use SNMPv2c bulk requests to walk the
        LLDP data, otherwise it will use SNMPv1c walks (much slower).

        When finished the LLDP data is collected in operation.data.
        """
        if not self.is_alive():
            raise RuntimeError("Cannot walk LLDP - Thread not running")
        # Create and start the LLDPOperation.
        operation = LLDPOperation(self, agent, community=community, bulk=bulk,
                                  op_retries=op_retries, timeout=timeout,
                                  op_timeout=op_timeout, callback=callback)
        if block is True:
            operation.wait()
        return operation
#end class SnmpThread(UdpThread)


# add_credentials(engineId=b'\x80\x00\x1f\x88\x03\x00\x02\xc5\x1c\xc8{',
#                 userName=b'administrator', authSecret='trustbutverify',
#                 privSecret='customer', hashFunc=sha1, cipher=AES)
TEST1_SHA1_AES128 = b'0\x81\x82\x02\x01\x030\x0f\x02\x02\x07J\x02\x03\x00\xff\xe3\x04\x01\x07\x02\x01\x03\x04=0;\x04\x0b\x80\x00\x1f\x88\x03\x00\x02\xc5\x1c\xc8{\x02\x01\x01\x02\x02\x00\xaa\x04\radministrator\x04\x0ca\xb8\xb42\xec\xdb\xc2/\xc6F\xf6G\x04\x08\xf8P\xdbA\x9d\xd1\t\xbb\x04-\xab4%\x14V\x94\x07\n\x88\x15\xdc\xcdb\xc1M\xc1\xf4=\x04\xcfm\xb8\xcc\xc2\xd9[e`\x81\x9f,\x81R\xd1Nx\xe9\xcc\x18\xbb\xdex\xf0\x8e\xb3'
TEST2_SHA1_AES128 = b'0\x81\x88\x02\x01\x030\x0e\x02\x02\x07J\x02\x02\x05\xc0\x04\x01\x03\x02\x01\x03\x04=0;\x04\x0b\x80\x00\x1f\x88\x03\x00\x02\xc5\x1c\xc8{\x02\x01\x01\x02\x02\x00\xaa\x04\radministrator\x04\x0c?\xc1\xda.\xf8>\xd5\x8b\xa7v\xe1\xb9\x04\x08hZ\xb6\xc2\xa4\xa4\xfe\xba\x044\xc0\x91\x07\x99\xb0\xa6*\xbe\xa12G\xe1e\x82aoI\x06eK\x8c\xfc\xbb\x89\x1bF\x0c\xee\x08(\x04m\xf4h\xfc\xac\xfb\x8f\xaf\x9c\xef\x9c\xef\xdd\xaa\x9azz\x82\xbb3<'
# add_credentials(engineId=b'\x80\x00\x01\xdc\x03\x00\x02\x99\x15.\xd5',
#                 userName=b'administrator', authSecret='5288sandbox',
#                 privSecret='LiebertCRV', hashFunc=md5, cipher=DES)
TEST1_MD5_DES = b'0\x81\x85\x02\x01\x030\x0f\x02\x02&o\x02\x03\x00\xff\xe3\x04\x01\x07\x02\x01\x03\x04=0;\x04\x0b\x80\x00\x01\xdc\x03\x00\x02\x99\x15.\xd5\x02\x01\x01\x02\x02\x00\xa1\x04\radministrator\x04\x0c\xa0\xa4[\xe2K\x83\xa0S\x19G\x12\xb2\x04\x08\x00\x00\x00\x01\x8b\x7f\xb3\x85\x040[:\xa2\xbb\x8e\xa4\x0e\xcdk\xb2\x8f#\xc4\xdd]S\xe7\x1d;Z\xc0bx\xa5\x94!\x1a\x88\xca\x7f\xa4T\x971\xf1T\xb7\xcf\x81)\xdb\xbb\xed\xb7M\xa3)^'
# Test commands
# import asnmp
# snmp = SnmpThread(debug=True)
# snmp.start()


def start(**kwargs):
    """Return a new, started and running SnmpThread instance."""
    thread = SnmpThread(**kwargs)
    thread.start()
    return thread


# ---------------------------------------------------------------------
# Simple console-based net scanner if run as a program. Can sweep an
# entire subnet (254 IP addresses) in about 5 seconds. Doing this
# same thing with pysnmp would take a minute and a half.
if __name__ == "__main__":
    import sys              # Python system
    import struct           # Packed 32-bit IP operations
    import argparse         # GNU-style argument parsing
    import asnmp

    # Create dictionary of SNMP v2 management OIDs.
    OID_NAMES = {asnmp.sysDescr: "Description",     # sysDescr (string)
                 asnmp.sysObjectID: "DeviceOID",    # sysObjectID (OID)
                 asnmp.sysUpTime: "UpTime",         # sysUpTime (TimeTicks)
                 asnmp.sysContact: "Contact",       # sysContact (string)
                 asnmp.sysName: "DomainName",       # sysName (string)
                 asnmp.sysLocation: "Location",     # sysLocation (string)
                 }

    # Create and configure argument parser.
    # sys.argv.append("172.17.141.1")    # DEBUG
    description = ("Perform mass SNMP get on an entire subnet.")
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

    # Create and start SNMP Thread
    snmp_thread = asnmp.start(debug=int(args.debug), throttle=args.throttle)
    # Schedule GETs to be deposited into a queue.
    ops = []
    for num in range(1, 255):
        agent = ".".join(str(((subnet + num) >> i) & 0xFF) for i in (24, 16, 8, 0))
        ops.append(snmp_thread.getMany(agent, OID_NAMES.keys(), block=False))
        # for oid in OID_NAMES:
        #    ops.append(snmp_thread.get(agent, oid, block=False))

    # Wait for operations to finish ------------------------------------
    t0 = time.time()
    while snmp_thread.is_alive() and not all(op.finished for op in ops):
        print('%s, %-40s%s' % ('Idle' if snmp_thread.idle else 'Busy',
              snmp_thread.status, '\b' * 72))
        time.sleep(1.0)
    elapsed = abs(time.time() - t0)
    print('%s, %-40s - Took %.3fs' % ('Idle' if snmp_thread.idle else 'Busy',
                                      snmp_thread.status, elapsed))
    # Collect all successful replies
    ok = [op for op in ops if op.ok is True]
    print("%d ok replies" % len(ok))
    results = []
    for operation in ok:
        if sysDescr not in operation.oids:
            continue
        results.append((operation.host, operation.oids.get(sysDescr)))
    for host, descr in sorted(results):
        print("%s\t%-40s" % (host, descr[:40]))

    # Stop thread and exit
    snmp_thread.stop(block=True)
    print("End of line")
    sys.exit(0)
