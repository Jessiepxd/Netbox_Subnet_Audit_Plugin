#=======================================================================
# ahttp.py - Asynchronous HTTP thread
#=======================================================================
"""Asynchronous HTTP thread optimized for mass polling of devices.

Supports both HTTP and HTTPS protocols. The worker thread establishes
one connection per host and all requests are serialized to a specific
host/port combination. The API is somewhat similar to 'requests'.

Asynchronous API:
All methods return an 'operation' object. This object holds the status
and result of the operation. By defaults all methods block until the
operation is finished unless the 'block=False' argument is passed.
All operation objects have the following attributes:
    operation.ok = True if the operation completed with no errors.
    operation.finished = True when the operation has completed.
    operation.error = Blank string if no errors (ok=True) otherwise
                      will contain a description of the error.
    operation.elapsed = Time in seconds the operation ran for.

WebEASY Support:
There are dedicated methods for performing WebEASY requests on cards.
If a card responds to a GET for /version.txt it likely supports one of
the two defined WebEASY APIs:
    cfgWeb - Older API. Deprecated and removed from v1.5 and later.
    cfgJSON - Current API. Supported by WebEASY v1.4 and newer.

- "1@s" = Product Name (e.g. "570IPG-X19")
- "2@s" = Software Creation Date (e.g. "20180207")
- "3@i" = Software Revision Major (e.g. 1)
- "4@i" = Software Revision Minor (e.g. 0)
- "6@s" = Software Build/Release (e.g. "0452-App F")
- "8@s" = Serial Number (e.g. "7678130045")
- "9@s" = Board Name (e.g. "570IPG")
- "10@s" = Board Revision (e.g. "A")
- "11@i" = Hardware Build (e.g. "2")
- "9150@s" = Alias String (e.g. "F0S1-2110IPG-Antenna")

EXAMPLE USAGE - SIMPLE GET:
>>> import ahttp
>>> http = ahttp.start()
>>> op = http.get("http://172.17.141.231/version.txt")
>>> op.finished
True
>>> op.ok
True
>>> op.status
'HTTP/1.1 200 OK'
>>> op.error
''
>>> op.elapsed
0.019999980926513672
>>> op.content
'name WebEASY\\r\\nV150B20152605-0000'

EXAMPLE USAGE - cfgJSON GET for '1@s' (Product Name)
>>> op = http.get_cfgjson("172.17.141.231", ['1@s'])
>>> op.ok
True
>>> op.result
{'1@s': 'EXE-NCS'}
>>>
"""
import os                       # For strerror()
import sys                      # Python system.
import ssl                      # Secure Sockets Layer (TLS)
import time                     # Python timing.
import errno                    # Standard C library error codes.
import socket                   # Python socket module.
import random                   # Random ID generation
import base64                   # Base64 encoding for basic authentication.
import asyncore                 # Asynchronous TCP sockets.
import traceback                # Logging of exceptions caught in thread.
import threading                # Python threading module
try:
    import urllib2
    from urllib2 import quote               # Python 2.7 urllib2 functions.
    urlparse = urllib2.urlparse.urlparse
    urlunparse = urllib2.urlparse.urlunparse
except ImportError:
    from urllib.parse import quote          # Python 3 urllib functions.
    from urllib.parse import urlparse
    from urllib.parse import urlunparse
try:
    import Queue                # Synchronized Queue
    from collections import Mapping
except ImportError:
    import queue as Queue       # Python3 compatibility.
    from collections.abc import Mapping
import json                     # JSON (encodes 2x faster than simplejson)
import simplejson               # Modern JSON (decodes 10x faster than json)
## Python 2.7: Note that simplejson returns str instead of unicode strings.
## simplejson v3.16.0 (with C extension) dumps takes ~100ms, loads takes 39ms!
## native json v2.0.9 (with C extension) dumps takes ~50ms, loads takes ~420ms!
## With Python 3.8 both modules are identical.


# Python 2/3 compatibility definitions ---------------------------------
if sys.version_info[0] == 2:
    ## Python2 BYTES convert unicode to str, otherwise pass str,bytes,bytearray
    ## and convert everything else to bytes with str() (identical to bytes()).
    BYTES = lambda text, encoding='utf8': (
        text.encode(encoding, 'replace') if isinstance(text, unicode) else
        text if hasattr(text, 'decode') else str(text))
    ## Python2 STR convert unicode to str. For str/bytes/bytearray encode to
    ## unicode then to str to remove invalid characters, otherwise attempt
    ## to convert directly to unicode for integers/None/floats/etc..
    STR = lambda data, encoding='utf8': (
        data.encode(encoding, 'replace') if isinstance(data, unicode) else
        (data.decode(encoding, 'replace').encode(encoding, 'replace'))
         if hasattr(data, 'decode') else str(data))
else:
    ## Python3 BYTES convert str to bytes, otherwise pass (bytes, bytearray)
    ## and convert everything else to str() first, then encode to bytes.
    BYTES = lambda text, encoding='utf8': (
        bytes(text, encoding, 'replace') if isinstance(text, str) else
        text if hasattr(text, 'decode') else str(text).encode(encoding))
    # Python3 STR pass if already str, otherwise convert to string.
    STR = lambda data, encoding='utf8': (
        data if isinstance(data, str) else
        (str(data, encoding, 'replace') if hasattr(data, 'decode') else
         str(data)))
    basestring = (str, bytes)

# Module Defines -------------------------------------------------------
VERSION = 0.1       # Initial version - July 10, 2018
VERSION = 0.2       # Functional version - August 22, 2018
VERSION = 0.3       # Added CfgWeb/CfgJson methods - September 7, 2018
VERSION = 0.4       # Reconnect bug fix
VERSION = 0.5       # Won't copy request data references (save memory).
VERSION = 0.6       # Added https option to cfgWeb and cfgJSON requests.
VERSION = 0.7       # Try to decode JSON twice, strips newlines on 2nd attempt.
VERSION = 0.8       # Added socket limit to socket_map for asyncore.wait().
VERSION = 0.9       # Legacy cfgWeb handling, better cfgJson result.
VERSION = 0.95      # cfgWeb queue and callback, report exceptions in callback.
VERSION = 0.96      # Looser legacy cfgWeb parsing (for replies missing Time)
VERSION = 0.97      # Support set_cfgWeb JSON replies, strip control characters.
VERSION = 0.98      # cfgJSON '@j' hack and don't convert values to string.
VERSION = 0.99      # Disabled "turbo" logic to use less CPU, larger chunksize.
VERSION = 1.00      # Larger read chunksize, flag error for truncated content.
VERSION = 1.01      # Fixed self.ok=True on timeout
VERSION = 1.02      # Use simplejson for decoding (10x faster than json.loads)
VERSION = 1.03      # cfgJSON GET manual encoding (3x faster than json.dumps)
VERSION = 1.04      # cfgJSON BULK GET, better reconnection handling.
VERSION = 1.05      # Bulk get progress, bug fixes
VERSION = 1.06      # CfgJsonBulk renamed to CfgJsonInst, added cancel method.
VERSION = 1.07      # Added path argument to all CfgJSON/CfgWeb methods.
VERSION = 1.08      # Tweak to CfgWebOperation for /cgi-bin/cfgjson requests.
VERSION = 1.09      # Shutdown and clear dispatchers after 2minute idle time.
VERSION = 1.10      # Fixed possible exception on error if reason is None.
VERSION = 1.11      # Fix bug with dispatcher shutdown/clear after idle.
VERSION = 1.12      # Fixed errno compare for EAGAIN/EINPROGRESS/EWOULDBLOCK
VERSION = 1.13      # Do not convert JSON integer values to string
VERSION = 1.14      # Error strings now contain status code and reason.
VERSION = 1.15      # Added get_cfgweb_safe() method and operation class.
VERSION = 1.16      # GetCfgWeb now converts integer VarID (@i) values to ints.
VERSION = 1.17      # WebEASY Feb 2020 or later now requires authentication.
                    # Added CfgJsonAuth() operation to login automatically.
                    # Changed default get_cfgjson() method to use that.
VERSION = 1.18      # Patched req_url into CfgJsonAuth.
VERSION = 1.20      # Initial Python3 compatibility build.
VERSION = 1.21      # Added start() convenience function.
VERSION = 1.22      # Added basic authentication.
VERSION = 1.30      # Revamp python2/3 compatibility, add multipart encoding.
VERSION = 1.31      # Add warnings to HttpOperation and note redirects.
VERSION = 1.32      # Add HTTP status to error on redirect/partial failures.
VERSION = 1.33      # Respect HTTP port, timeout dispatchers, make cfgJSON more
                    # compatiable, and fix python2 freeze bug.
VERSION = 1.34      # Fix JSONRPC error extraction and NATX authentication.
VERSION = 1.35      # Differentiate self.started, self.timestamp timestamps.

WINSOCK_CODES = {   # Since os.strerror() doesn't support these.
    10004: "Interrupted function call",                 # WSAEINTR
    10009: "File handle is not valid",                  # WSAEBADF
    10013: "Permission denied",                         # WSAEACCES
    10014: "Bad address",                               # WSAEFAULT
    10022: "Invalid argument",                          # WSAEINVAL
    10024: "Too many open files",                       # WSAEMFILE
    10035: "Resource temporarily unavailable",          # WSAEWOULDBLOCK
    10036: "Operation now in progress",                 # WSAEINPROGRESS
    10037: "Operation already in progress",             # WSAEALREADY
    10038: "Socket operation on nonsocket",             # WSAENOTSOCK
    10039: "Destination address required",              # WSAEDESTADDRREQ
    10040: "Message too long",                          # WSAEMSGSIZE
    10041: "Protocol wrong type for socket",            # WSAEPROTOTYPE
    10042: "Bad protocol option",                       # WSAENOPROTOOPT
    10043: "Protocol not supported",                    # WSAEPROTONOSUPPORT
    10044: "Socket type not supported",                 # WSAESOCKTNOSUPPORT
    10045: "Operation not supported",                   # WSAEOPNOTSUPP
    10046: "Protocol family not supported",             # WSAEPFNOSUPPORT
    10047: "Address family not supported by protocol family",  # WSAEAFNOSUPPORT
    10048: "Address already in use",                    # WSAEADDRINUSE
    10049: "Cannot assign requested address",           # WSAEADDRNOTAVAIL
    10050: "Network is down",                           # WSAENETDOWN
    10051: "Network is unreachable",                    # WSAENETUNREACH
    10052: "Network dropped connection on reset",       # WSAENETRESET
    10053: "Software caused connection abort",          # WSAECONNABORTED
    10054: "Connection reset by peer",                  # WSAECONNRESET
    10055: "No buffer space available",                 # WSAENOBUFS
    10056: "Socket is already connected",               # WSAEISCONN
    10057: "Socket is not connected",                   # WSAENOTCONN
    10058: "Cannot send after socket shutdown",         # WSAESHUTDOWN
    10059: "Too many references",                       # WSAETOOMANYREFS
    10060: "Connection timed out",                      # WSAETIMEDOUT
    10061: "Connection refused",                        # WSAECONNREFUSED
    10062: "Cannot translate name",                     # WSAELOOP
    10063: "Name too long",                             # WSAENAMETOOLONG
    10064: "Host is down",                              # WSAEHOSTDOWN
    10065: "No route to host",                          # WSAEHOSTUNREACH
    10066: "Directory not empty",                       # WSAENOTEMPTY
    10067: "Too many processes",                        # WSAEPROCLIM
    10068: "User quota exceeded",                       # WSAEUSERS
    10069: "Disk quota exceeded",                       # WSAEDQUOT
    10070: "Stale file handle reference",               # WSAESTALE
    10071: "Item is remote",                            # WSAEREMOTE
    10091: "Network subsystem is unavailable",          # WSASYSNOTREADY
    10092: "Winsock.dll version out of range",          # WSAVERNOTSUPPORTED
    10093: "Successful WSAStartup not yet performed",   # WSANOTINITIALISED
    10101: "Graceful shutdown in progress",             # WSAEDISCON
}
ALPHANUMERIC = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
PROFILING = []

# ----------------------------------------------------------------------
class HttpOperation(object):
    '''Base class to manage a single HTTP operation.

    The supplied parameters are parsed into:
        self.req_url = Original request URL
        self.scheme = The scheme of the request.
        self.address = Tuple of (hostname, port) parsed from URL.
        self.data = Request body as `bytes`. If 'data' is a list of
                    (key, value) tuples, or a dictionary, it will be
                    form-encoded as bytes. Otherwise it is sent as-is.
        self.files = Create multipart MIME encoded body.
        self.query_string = Actual query string generated from 'params'.
        self.req_headers = Request headers as a dictionary.
        self.allow_redirects = True to follow redirects.
        self.callback = The specified callback function.
        self.queue = A Queue() object to add to once we are completed.
        self.timeout = Request timeout in seconds.
        self.auth = 2-tuple of (username, password) either specified in
                    the constructor, or extracted from the URL.
        self.request = The actual HTTP request and headers sent to the
                       server as `bytes`.
        self.cookies = Can be used to force cookies for this operation.
                       Empty dictionary by default. A copy is made and
                       it is updated with dispatcher's cookies.

    If 'files' is specified, it must be a dictionary or list in the
    format { field_name: FileInfo } or [ (field_name, FileInfo), ... ]
    where 'FileInfo' is either file data, a file-like object, or a
    2/3/4-tuple of (filename, filedata/obj, content_type, partheaders).
    The body is generated into a multipart MIME format using the given
    boundary_delim (if specified, otherwise random). In this case 'data'
    will be used as the preamble if it is also specified.

    As the operation is processed the following attributes are updated:
        self.sent = Number of bytes of the request that have been sent.
        self.active = True if the thread is currently processing this.
        self.finished = True once the thread finishes this operation.

    Once the request is complete, the following attributes will be set:
        self.elapsed = Time from sending the request to getting a reply.
        self.url = Final URL of this reply (after possible redirects).
        self.status = Full HTTP status text (e.g. "HTTP/1.1 200 OK").
        self.status_code = Integer code from self.status (e.g. 200).
        self.reason = Text split from self.status (e.g. "Not Found")
        self.headers = Server response headers as a dictionary.
        self.content = The content of the reply in bytes. Can be `None`
                       if no content.
        self.ok = True if reply was received OK.
        self.error = Blank string or error message that occurred.
        '''
    HTTP_VERSION = b"HTTP/1.1"

    def __init__(self, URL, method, data=None, params=None, files=None,
                 delim='&', boundary_delim=None, auth=None, safe=',',
                 headers={}, allow_redirects=True, max_redirects=2,
                 callback=None, queue=None, timeout=4.0, cookies={}):
        # Save parameters.
        self.req_url = URL                  # Original request URL
        self.method = method.upper()        # GET, HEAD, POST, PUT, etc..
        self.req_headers = {STR(key): STR(value)    # Force to string
                            for key,value in headers.items()}
        self.allow_redirects = bool(allow_redirects)
        self.max_redirects = int(max_redirects)
        self.callback = callback
        self.queue = queue
        self.timeout = float(timeout)
        self.auth = auth
        self.address = ('', 0)
        self.scheme = self.path = self.params = ''
        self.query_string = self.fragment = ''
        self.cookies = dict(cookies)    # Make copy as it will be updated.
        # Set response attributes.
        self.sent = 0                   # Bytes sent to the server.
        self.active = False             # True when response is being processed.
        self.finished = False           # True when operation is completed.
        self.num_redirects = 0          # Number of redirects we followed.
        self.started = False            # Time the operation was started.
        self.timestamp = None           # Time the last request was sent.
        self.elapsed = 0                # Time elapsed for this operation.
        self.status = None              # None = status line not received yet.
        self.status_code = 0            # Integer status_code of self.status.
        self.reason = ""                # Reason portion of self.status.
        self.headers = {}               # Response headers parsed into here.
        self.content = b""              # Response content as raw string.
        self.ok = False                 # True if successful response received.
        self.error = ""                 # Error associated with response.
        self.warnings = []              # Additional warnings strings to error.
        # Parse the URL. Creates self.address and sets self.headers['Host'].
        self.set_URL(URL)
        # Generate the query string from supplied 'params'.
        if isinstance(params, str):
            self.query_string = params
        elif params:
            if isinstance(params, dict):
                # Convert dictionary to list of tuples (sorted for consistency).
                params = sorted(params.items())
            if hasattr(params, '__iter__'):
                # Params is a sequence of (key,value) tuples. Join it.
                self.query_string = delim.join(
                    # Using STR here to allows key/value to be integer/floats.
                    "%s=%s" % (quote(STR(key), safe), quote(STR(value), safe))
                    if value is not None else quote(key, safe)
                    for key, value in params)
            else:
                # Params not a dict or list. Convert to string.
                self.query_string = STR(params)
        # Generate the body of the requests from supplied 'data' or 'files'.
        self.data = b''
        if isinstance(data, Mapping) or isinstance(data, list):
            # Generate form urlencoded body data.
            if isinstance(data, Mapping):
                # Flatten dictionary to list of tuples (sorted for consistency).
                data = sorted(data.items())
            # Form-encode the data.
            self.data = BYTES(delim.join(
                # Using STR here allows key/value to be integer/floats.
                "%s=%s" % (quote(STR(key), safe), quote(STR(value), safe))
                if value is not None else quote(key,safe)
                for key, value in data))
            # Patch Content-Type in the headers (if not specified).
            if 'Content-Type' not in self.req_headers:
                self.req_headers['Content-Type'] = "application/x-www-form-urlencoded"
        elif data:
            # String data. Copy reference if bytes, otherwise utf-8 encode.
            self.data = BYTES(data)
            if 'Content-Type' not in self.req_headers:
                self.req_headers['Content-Type'] = "application/octet-stream"
        if files:
            # Generate multipart MIME attachment and append to body data.
            CONTENT_DISPOSITION = b'Content-Disposition: form-data; name="%s"'
            CONTENT_TYPE = b'Content-Type: %s'
            if boundary_delim is None:
                # Copy Chrome/Safari's boundary format for max compatibility.
                boundary_delim = BYTES("----WebKitFormBoundary%s" %
                                       ''.join(random.sample(ALPHANUMERIC, k=16)))
            if isinstance(files, Mapping):
                # Flatten dictionary to sequence of (key, value) pairs.
                files = files.items()
            multiparts = []
            for field_name, file_data in files:
                # Opening boundary
                multiparts.append(b"--%s" % boundary_delim)
                file_name = file_type = file_headers = None
                # Unpack file_data if it is a 2/3/4-tuple/list of values.
                if isinstance(file_data, (tuple, list)):
                    if len(file_data) == 2:
                        file_name, file_data = file_data
                    elif len(file_data) == 3:
                        file_name, file_data, file_type = file_data
                    else:
                        file_name, file_data, file_type, file_headers = file_data
                if isinstance(file_data, (str, bytes, bytearray)):
                    # Raw data, no filename in content disposition.
                    pass
                elif hasattr(file_data, 'read'):
                    # File-like object. Read bytes and guess filename.
                    if not file_name:
                        name = getattr(file_data, 'name', None)
                        if (name and isinstance(name, basestring) and
                            name[0] != '<' and name[-1] != '>'):
                            file_name = os.path.basename(name)
                    file_data = file_data.read()
                else:
                    continue    # Blank or None for file_info. Skip.
                ## Generate headers. Escape parameters according to:
                ## https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#multipart-form-data
                field_name = (BYTES(field_name).replace(b'\x0a', b'%0A')
                              .replace(b'\x0d', b'%0D').replace(b'\x22', b'%22'))
                content_disposition = CONTENT_DISPOSITION % field_name
                if file_name:
                    file_name = (BYTES(file_name).replace(b'\x0a', b'%0A')
                                 .replace(b'\x0d', b'%0D').replace(b'\x22', b'%22'))
                    content_disposition += b'; filename="%s"' % file_name
                multiparts.append(content_disposition)
                if file_type:
                    multiparts.append(b'Content-Type: %s' % BYTES(file_type))
                multiparts.append(b'')
                multiparts.append(BYTES(file_data))
            # Closing distinguised boundary
            multiparts.append(b"--%s--\r\n" % BYTES(boundary_delim))
            # Convert to data.
            self.data = b'\r\n'.join(multiparts)
            if 'Content-Type' not in self.req_headers:
                content_type = "multipart/form-data; boundary=%s" % STR(boundary_delim)
                self.req_headers['Content-Type'] = content_type
        # Patch any missing headers that are required.
        if self.data and 'Content-Length' not in self.req_headers:
            # Content-Length required for keepalive connections.
            self.req_headers['Content-Length'] = STR(len(self.data))

    def set_URL(self, URL):
        '''Set the operation's active URL. It gets parsed to:

            self.scheme = scheme
            self.auth = (username, password)
            self.address = (hostname, port)
            self.path = path
            self.params = params
            self.query_string = query
            self.fragment = fragment
        May raise ValueError if the URL cannot be converted to a string
        or the scheme/hostname is missing.
        '''
        # Parse the URL, forcing conversion to a raw string.
        url_parts = urlparse(URL)
        # Change self.scheme if specified.
        schema_change = False
        if url_parts.scheme:
            # Was our scheme previously set and is now changing?
            if self.scheme and self.scheme != url_parts.scheme:
                schema_change = True
            self.scheme = url_parts.scheme.lower()
        if not self.scheme:
            raise ValueError("URL '%s' missing schema (e.g. http://)" % URL)
        # Change self.auth, if username/password specified in the URL.
        username, password = self.auth if self.auth else (None, None)
        username = url_parts.username if url_parts.username else username
        password = url_parts.password if url_parts.password else password
        self.auth = (username, password)
        # Change self.address (hostname, port), if specified.
        hostname, port = self.address
        hostname = url_parts.hostname if url_parts.hostname else hostname
        port = url_parts.port if url_parts.port else port
        # Must have a hostname. Can set port from self.scheme.
        if not hostname:
            raise ValueError("URL '%s' missing hostname" % URL)
        if not port or schema_change is True:
            # Force port update if we've switched scheme.
            port = 443 if self.scheme == 'https' else 80
        self.address = (hostname, port)
        # Change self.path, if new location specified.
        if url_parts.path:
            self.path = url_parts.path
        if not self.path.startswith('/'):
            self.path = '/' + self.path
        # Change self.params, if new parameters specified.
        if url_parts.params:
            self.params = url_parts.params
        # Change self.query_string if query specified.
        if url_parts.query:
            self.query_string = url_parts.query
        # Change self.fragment if fragment specified.
        if url_parts.fragment:
            self.fragment = url_parts.fragment
        # Add hostname to request headers (required by HTTP v1.0+)
        self.req_headers['Host'] = hostname

    def generate_request(self, cookies=None):
        '''Generate self.request, optionally including cookies.'''
        # Add basic authentication header if self.auth was specified.
        if self.auth and all(self.auth):
            username, password = self.auth
            self.req_headers['Authorization'] = "Basic %s" % STR(
                base64.b64encode(b'%s:%s' % (BYTES(username), BYTES(password))))
        # Add given cookies to request header.
        if cookies:
            self.cookies.update(cookies)
        if self.cookies:
            cookie = '; '.join("%s=%s" % item for item in self.cookies.items())
            self.req_headers['Cookie'] = cookie
            #print("Cookie: %s" % cookie)
        # Generate request headers as a string.
        headers = ''.join("%s: %s\r\n" % (key, value)
                          for key,value in self.req_headers.items())
        # Don't allow a blank path. Set it to '/' as a minimum.
        location = self.path if self.path else '/'
        # Generate request string.
        params = b';'+BYTES(self.params) if self.params else b''
        query = b'?'+BYTES(self.query_string) if self.query_string else b''
        frag = b'#'+BYTES(self.fragment) if self.fragment else b''
        self.request = (b"%s %s%s%s%s %s\r\n%s\r\n" %
                        (BYTES(self.method), BYTES(location), params, query,
                         frag, self.HTTP_VERSION, BYTES(headers)))
        # Update URL. TODO: Maybe leave out port if default port is used?
        new_url_parts = (self.scheme, '%s:%s' % self.address, location,
                         self.params, self.query_string, self.fragment)
        self.url = urlunparse(new_url_parts)

    def start(self, cookies=None):
        # Flag us as active and reset sent bytes count.
        self.active = True
        self.finished = False
        self.sent = 0
        # Generate self.request.
        self.generate_request(cookies=cookies)
        # If this is the first request for this operation set start timestamp.
        if not self.started:
            self.started = time.time()
        # Mark timestamp for this current request (updated each redirect).
        self.timestamp = time.time()

    def redirect(self, code, location):
        '''Redirect this operation to the new location supplied.

        Reconfigures the operation to get the new URL, depending on the
        redirection code type. Returns True if the re-configuration was
        successful, False otherwise (i.e. too many redirects).'''
        # Check against redirection count.
        self.num_redirects += 1
        if self.num_redirects > self.max_redirects:
            return False
        # Only codes 307 and 308 keep the method and body.
        if code in (301, 302, 303):
            # Force method to GET and clear body (for security reasons).
            if self.data:
                self.warnings.append("%s data cleared" % self.method)
            self.method = 'GET'
            self.data = b''
            # Get rid of any POST/PUT headers that might be in there.
            self.req_headers.pop('Content-Type', None)
            self.req_headers.pop('Content-Length', None)
        # Convert location back to a string, if necessary.
        if type(location) is bytes:
            try:
                location = location.decode('utf8')
            except ValueError as err:
                # Reject malformed locations.
                return False
        # Modify operation for redirection URL.
        self.set_URL(STR(location))
        return True

    def finish(self, status_code, content, reason, error):
        '''Called when an operation is finished by a dispatcher.

        Any parameter might be `None` if not received yet.
        If timed out or disconnected the 'error' parameter will be
        passed containing a string describing the error that occurred.
        '''
##        print("Operation '%s' finished. Status='%s', error='%s'" %
##              (self.req_url, self.status, error))
        # Store the values.
        self.elapsed = 0
        if self.started:
            self.elapsed = abs(time.time() - self.started)
        self.status_code = status_code
        self.content = content
        self.reason = reason
        self.error = error
        self.ok = False
        self.timestamp = None
        # If we got redirectd, add a warning for that.
        if self.num_redirects:
            self.warnings.append("redirected %s times" % self.num_redirects)
        # Set self.ok to True if we got a successful status_code with no error.
        if status_code is not None:
            if status_code < 400:
                if not self.error:
                    self.ok = True
            else:
                # Failed status code. Make sure self.error gets set.
                if self.error:
                    self.error += self.status
                else:
                    self.error = self.status
                # Add any warnings onto the error message.
                if self.warnings:
                    self.error += ' (%s)' % (', '.join(self.warnings))
        # Flag error if we couldn't send the entire request string.
        if self.sent > 0 and self.sent < (len(self.request) + len(self.data)):
            send_error = (" - Request partially sent %d/%d bytes" %
                          (self.sent, (len(self.request) + len(self.data))))
            self.error = self.status if not self.error else self.error
            self.error = self.error + send_error
            self.ok = False
        # Allow finishing tasks to be performed before marked as finished.
        self.handle_finish()
        self.active = False
        self.finished = True
        # Add ourselves to the caller's queue, if one was specified.
        if self.queue:
            self.queue.put(self)
        # Call the callback function, if specified.
        if callable(self.callback):
            try:
                self.callback(self)
            except Exception as err:
                if self.error:
                    self.error += " - "
                self.error = self.error + "Callback exception: %s" % err
                traceback.print_exc()

    def handle_finish(self):
        '''Can be sub-classed. Called when the operation completes but
        before self.finished is set to True and before any callbacks.'''
        pass
#end class HttpOperation(object)



class HttpDispatcher(asyncore.dispatcher):
    '''Class to manage a single connection to an HTTP server.

    Will send HTTP requests queued with the add_operation() method.
    Will auto-reconnect to the host if disconnected.
    '''
    ## These two values should ideally be the same.
    ## BUFFSIZE = 8192/8192 (window default) = 1:31 to send 71,137,972 bytes.
    ## BUFFSIZE = 8192/16384 = 0:45 to send 71,137,972 bytes.
    ## BUFFSIZE = 8192/32768 = 0:28 to send 71,137,972 bytes.
    ## BUFFSIZE = 8192/65535 = 0:28 to send 71,137,972 bytes.
    ## BUFFSIZE = 16384/8192 = 1:31 to send 71,137,972 bytes.
    ## BUFFSIZE = 16384/16384 = 0:45 to send 71,137,972 bytes.
    BUFFERSIZE = 8192       # Force this size on new sockets (commented out).
    WRITE_CHUNKSIZE = 32768 # Chunk size to use when writing sockets.
    ## 1024 =  20MB in 100s (200kB/s)       (200*1024 = 204kB/s)
    ## 8192 =  64MB in 49.4s (1,295kB/s)    (200*8192 = 1,638kB/s)
    ## 16384 = 64MB in 45.9s (1,394kB/s)    (200*16384 = 3,276kB/s)
    READ_CHUNKSIZE = 8192   # Chunk size to use when reading sockets.
    ssl_context = ssl.create_default_context()
    # HACK: Use ultra-low security settings for SSL to ignore errors.
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    def __init__(self, parent, socket_map, debug=False):
        # Call original constructor
        asyncore.dispatcher.__init__(self, map=socket_map)
        self.parent = parent
        self.debug = bool(debug)
        self.operation = None
        self.op_list = []
        self.cookies = {}
        self.reuse_connection = False
        self.last_active = time.time()
        # Reset input and output buffer attributes.
        self.reset()

    def reset(self):
        '''Reset receive attributes and dispatcher_with_send output buffer.'''
        # Attributes used to receive the HTTP response.
        #self.log_info("reset()")
        self.in_buffer = bytearray()    # Receive buffer.
        self.sent = 0                   # Amount of operation's request sent.
        self.status = None              # HTTP response status line.
        self.body = None                # Buffer for body of reply.
        self.content_length = None      # Parsed from response headers.
        self.transfer_encoding = None   # Parsed from Transfer-Encoding.
        self.chunk_size = None          # Used for chunked encoding.
        self.chunk_term = False         # Flag chunked terminator was received.
        self.attempt_reconnect = False  # Flag to retry operation on disconnect.

    def clear_cookies(self):
        '''Clear all cookies accumulated over all connections to the host.'''
        self.cookies.clear()

    def log_info(self, message, type='info'):
        '''Override the log method to provide custom logging.'''
        # TODO: Implement logging in main thread.
        if self.debug:
            self.parent.log('dispatch: %s' % (message))
##            if self.operation:
##                print('%s: %s' % (self.operation.address, message))
##            else:
##                print('None: %s' % (message))

    def create_socket(self, scheme='http', hostname=None):
        '''Override create_socket to allow SSL wrapper for https scheme.'''
        # Create a new socket and put it into non-blocking mode.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(0)
        # Try to adjust send/receive buffer sizes (if necessary).
##        try:
##            for option in (socket.SO_RCVBUF, socket.SO_SNDBUF):
##                buffer_size = sock.getsockopt(socket.SOL_SOCKET, option)
##                if buffer_size < self.BUFFERSIZE:
##                    sock.setsockopt(socket.SOL_SOCKET, option, self.BUFFERSIZE)
##                    new_size = sock.getsockopt(socket.SOL_SOCKET, option)
##                    self.log_info("Adjusted %s buffersize from %d to %d" %
##                               ("RCV" if option == socket.SO_RCVBUF else "SND",
##                                buffer_size, new_size))
##        except socket.error:
##            pass
        if scheme == 'https':
            # Wrap socket in SSL layer.
            sock = self.ssl_context.wrap_socket(sock, server_hostname=hostname)
            # Should already be non-blocking but make sure.
            sock.setblocking(0)
        self.set_socket(sock)

    def handle_connect(self):
        '''Called when the socket first connects. No need to do anything.'''
        self.log_info("handle_connect()")
        pass

    def handle_write(self):
        '''Called when socket is ready for writing. Send request.'''
        #self.log_info("handle_write()")
        if self.operation:
            #self.log_info("handle_write: self.operation=%s" % repr(self.operation))
            sent = self.sent
            chunk = None
            if sent < len(self.operation.request):
                # Request line not finished sending yet. Send next chunk.
                chunk = self.operation.request[sent:sent+self.WRITE_CHUNKSIZE]
            else:
                # Find how much we sent of the request body.
                sent = sent - len(self.operation.request)
                if sent < len(self.operation.data):
                    # Body (data) not finished sending yet. Send next chunk.
                    chunk = self.operation.data[sent:sent+self.WRITE_CHUNKSIZE]
            # If there is a chunk to send, send it to the socket.
            if chunk:
                try:
                    # The send() method can call handle_close() if disconnected.
                    num_sent = self.send(chunk)
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    # SSL layer no data available yet. Ignore.
                    num_sent = 0
                # Connection might be closed if sent failed.
                if num_sent:
                    # Update amount sent and copy to operation attribute.
                    self.sent += num_sent
                    self.operation.sent = self.sent
                    self.last_active = time.time()
                    #self.log_info("Send %d (%d/%d) bytes" % (num_sent, self.sent, len(self.operation.request)+len(self.operation.data)))

    def handle_read(self):
        '''Socket has data to be read.

        Note that recv() may raise socket.error with EAGAIN or
        EWOULDBLOCK, even though select.select() or select.poll() has
        reported the socket ready for reading.
        '''
        #self.log_info("handle_read()")
        try:
            # Will call handle_close() if connection is dropped and return ''.
            data = self.recv(self.READ_CHUNKSIZE)
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            # SSL layer no data available yet. Ignore.
            #self.log_info("handle_read() SSLWantReadError ignored")
            return
        except socket.error as err:
            if err.errno in (errno.EINPROGRESS,errno.EWOULDBLOCK,errno.EAGAIN):
                # Ignore non-blocking errors.
                self.log_info("handle_read() WOULDBLOCK ignored")
                return
            # Actual error occured. Close the connection.
            self.log_info("handle_read() exception %s" % err)
            self.handle_close(error=str(err))
            return
        if data:
            #self.log_info("handle_read() data=%d bytes" % len(data))
            if not self.operation:
                self.log_info("Unsolicited %d bytes from server!" % len(data))
            else:
                # Add data to buffer and parse the HTTP reply on the fly.
                self.last_active = time.time()
                self.in_buffer.extend(data)
                self.parse_buffer()
        else:
            # Connection closed and handle_close() has been called.
            pass

    def handle_close(self, error=None):
        '''Called when other side has closed the connection.'''
        self.log_info("handle_close(error=%r) self.status=%s" % (error, self.status))
        # If an error occured try to read it from the socket.
        if error is None:
            error = self.get_socket_error()
        self.shutdown()
        # Were we trying to re-use the connection?
        if self.operation and self.reuse_connection and not self.status:
            ## Yes but we didn't get a reply (self.status) before the
            ## connection was closed. Reconnect and retry the operation.
            self.reuse_connection = False
            self.log_info("Connection dropped. Attempting to reconnect.")
            ## Reset our receiver then set attempt_reconect flag so that
            ## we reconnect in the next poll. This allows any pending
            ## events on the current socket to be handled properly.
            self.reset()
            self.attempt_reconnect = True
        else:
            # Disconnected. Did we finish the request?
            if self.operation and not self.status:
                if not error:
                    error = ("No response to request. Sent %d/%d" %
                             (self.sent, len(self.operation.request) +
                              len(self.operation.data)))
            self.finish_operation(error)

    def create_connection(self):
        '''Create a connection to the host for the current operation.'''
        # Start connection process.
        self.reuse_connection = False
        self.attempt_reconnect = False
        self.log_info("Creating socket and connecting to '%s:%d'" % self.operation.address)
        self.create_socket(self.operation.scheme, self.operation.address[0])
        # This may call self.handle_connect() right away.
        try:
            # NOTE: If address is invalid can BLOCK on getaddrinfo call.
            self.connect(self.operation.address)
        except socket.error as err:
            # Connect failed, likely bad address in redirect.
            error = "Failed to connect to '%s:%d'" % self.operation.address
            self.log_info(error)
            self.shutdown()
            self.finish_operation(error=error)

    def get_socket_error(self):
        '''Return error code read from self.socket into a string.'''
        if self.socket:
            try:
                code = self.socket.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
            except socket.error:
                return("Connection closed")
            else:
                if code in WINSOCK_CODES:
                    return(WINSOCK_CODES[code])
                elif code > 0:
                    return(os.strerror(code))
        # No socket defined or no error.
        return("")

    def shutdown(self, block=False):
        '''Called instead of close() to shutdown then close the socket.'''
        self.log_info("shutdown()")
        if self.socket:
            # Attempt to gracefully terminate connection.
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass
            if block is False:
                # Give up our timeslice as socket.close() can block for 10-20ms.
                time.sleep(0.001)
            self.close()

    def parse_buffer(self):
        '''Parse self.in_buffer into HTTP status, headers, and body.'''
        # Did we get the status line yet?
        if self.status is None:
            # No. Search buffer for EOL. If not found (-1) we need more data.
            pos = self.in_buffer.find(b'\r\n')
            if pos < 0:
                return
            self.status = STR(self.in_buffer[:pos])
            self.in_buffer = self.in_buffer[pos+2:]
        # Did we get the headers yet?
        if self.body is None:
            # No. Search for blank line. If not found (-1), wait for more data.
            pos = self.in_buffer.find(b'\r\n\r\n')
            if pos < 0:
                return
            # Remove header lines from self.in_buffer
            lines = STR(self.in_buffer[:pos]).splitlines()
            self.in_buffer = self.in_buffer[pos+4:]
            self.body = bytearray()
            # Parse headers.
            headers = [(name.strip().lower(), val.strip()) for name,sep,val in
                       (line.partition(':') for line in lines) if sep == ':']
            # Capitalize header field names (accounting for the dash)
            headers = [('-'.join(word.capitalize() for word in name.split('-')),
                        value) for name,value in headers]
            # Extract Set-Cookie values (since there may be multiple ones).
            for key, value in headers:
                if key.lower() == 'set-cookie':
                    name, equals, val = value.partition(';')[0].partition('=')
                    if equals == '=':
                        self.cookies[name.strip()] = val.strip()
                        self.log_info("* Set-Cookie: %s=%s" % (name, val))
            # Wrap into dictionary.
            self.operation.headers = dict(headers)
            # Search for Content-Length and set variable.
            self.content_length = None
            for key, value in self.operation.headers.items():
                if key.lower() == 'content-length' and value.isdigit():
                    self.content_length = int(value)
                    self.log_info("* Content-Length=%d" % self.content_length)
            # Search for Transfer-Encoding and set variable.
            self.transfer_encoding = None
            for key, value in self.operation.headers.items():
                if key.lower() == 'transfer-encoding':
                    self.transfer_encoding = value.lower()
                    self.log_info("* Transfer-Encoding=%s" % self.transfer_encoding)
        # Receiving body. Copy buffer reference to self.body.
        if self.transfer_encoding == 'chunked':
            # Decode chunked encoding.
            self.parse_chunked()
        else:
            # Identity encoding (no encoding). Copy reference to self.body.
            self.body = self.in_buffer
        # Did the server provide a Content-Length in the response headers?
        if self.content_length is not None:
            # Check if we've got the entire reply.
            if len(self.body) >= self.content_length:
                # Content length received. Split body out of in_buffer.
                self.log_info("Received %d/%d of Content-Length" %
                              (self.content_length, len(self.body)))
                self.body = self.in_buffer[:self.content_length]
                self.in_buffer = self.in_buffer[self.content_length:]
                error = ""
                if self.in_buffer:
                    error = "Got %d bytes extra in body" % len(self.in_buffer)
                self.finish_operation(error)

    def parse_chunked(self):
        '''Parse chunked encoding in self.in_buffer to self.body.'''
        while self.in_buffer:
            if self.chunk_size is None:
                # Need to decode chunk_size first.
                pos = self.in_buffer.find(b'\r\n')
                if pos < 0:
                    # Size not found yet. Abort operation if not found early.
                    if len(self.in_buffer) > 8:
                        self.handle_close(error="Bad chunked encoding")
                    break
                # Remove size from buffer (Python2 int() can't take bytearray).
                size = STR(self.in_buffer[:pos])
                self.in_buffer = self.in_buffer[pos+2:]
                try:
                    self.chunk_size = int(size, 16)
                except ValueError as err:
                    self.handle_close(error="Bad chunk size '%s'" % size)
                    break
            else:
                # Do we have full chunk yet and the terminator?
                if len(self.in_buffer) >= self.chunk_size + 2:
                    # Extract chunk and add to body.
                    self.body.extend(self.in_buffer[:self.chunk_size])
                    crlf = self.in_buffer[self.chunk_size:self.chunk_size+2]
                    self.in_buffer = self.in_buffer[self.chunk_size+2:]
                    if crlf != b'\r\n':
                        self.handle_close(error="Bad chunk CRLF %r" % crlf)
                        break
                    self.log_info("Got chunk %d bytes, buffer=%d bytes" %
                                  (self.chunk_size, len(self.in_buffer)))
                    if self.chunk_size == 0:
                        # Zero-length chunk completes response.
                        self.chunk_term = True
                        self.finish_operation('')
                        break
                    # Not done yet. Search for chunk_size again.
                    self.chunk_size = None
                else:
                    # Need more data for chunk.
                    break

    def add_operation(self, operation):
        '''Add operation to queue and start it immediately if nothing active.'''
        self.log_info("add_operation()")
        self.op_list.append(operation)
        if self.operation is None:
            # Nothing going on. Immediately start the next operation.
            self.start_operation()

    def poll(self):
        '''Poll current operation for timeout and do socket maintenance.

        Return last activity timestamp.
        '''
        # self.log_info("poll(operation=%s)" % repr(self.operation))
        if self.operation is None:
            # No operation active.
            return self.last_active
        # Check current operation for timeout.
        elapsed = 0
        if self.operation.timestamp:
            elapsed = abs(time.time() - self.operation.timestamp)
            self.operation.elapsed = elapsed
        # self.log_info("poll() %.1fsec/%.1fsec" % (elapsed, self.operation.timeout))
        if elapsed > self.operation.timeout:
            ## Since a read/write/connect may still be ongoing on the
            ## socket we must close it to ensure it stops completely
            ## for the next operation to start properly.
            self.shutdown()
            # Push operation to finished list with "timed out" error.
            self.finish_operation("Timed out %.1fsec" %
                                  self.operation.timeout)
        elif self.operation.scheme == 'https' and self.connected is True:
            ## Issue occasional reads on SSL-wrapped sockets since
            ## asyncore select() can't determine if data is ready.
            # self.log_info("SSL polling read(), in_buffer=%d" % len(self.in_buffer))
            self.handle_read()
        elif self.attempt_reconnect is True:
            self.log_info("Attempting to reconnect")
            self.create_connection()
        return self.last_active

    def start_operation(self):
        '''Try to start the next pending operation (if any).'''
        if self.operation is not None or not self.op_list:
            # Current operation still pending or queue empty.
            return
        self.log_info("start_operation() self.operation=%s" % repr(self.operation))
        # Pop next operation from the queue and reset attributes.
        self.operation = self.op_list.pop(0)
        # Start the operation.
        self.operation.start(cookies=self.cookies)
        # Reset our receiver attributes.
        self.reset()
        self.log_info("start_operation: %s" % self.operation.request.partition(b'\r\n')[0])
        if not self.connected:
            # Connect to host for self.operation.
            self.create_connection()
        else:
            ## Already connected. Attempt to reuse this connection. The
            ## next write may fail if the server dropped the connection.
            self.reuse_connection = True

    def finish_operation(self, error):
        '''Finish the current operation and start the next one.'''
        self.log_info("finish_operation(), self.operation=%s" % self.operation)
        operation = self.operation
        if operation:
            # Clear active operation.
            self.operation = None
            # Parse the response status.
            code = None
            reason = None
            operation.status = None
            if self.status:
                operation.status = self.status
                parts = self.status.split(None, 2)
                if len(parts) > 1 and parts[1].isdigit() is True:
                    code = int(parts[1])
                if len(parts) > 2:
                    reason = parts[2]
            # Is it a redirect?
            if code in (301, 302, 303, 307, 308):
                # Redirect. Was the location specified in the headers?
                location = [value for key,value in operation.headers.items()
                            if key.lower() == 'location']
                if location and operation.allow_redirects is True:
                    # Yes. Try to re-configure operation for new location.
                    location = location[0]
                    success = operation.redirect(code, location=location)
                    if success is True:
                        # Re-queue operation with parent thread.
                        self.log_info("Got %d redirect to location %s!" %
                                      (code, location))
                        self.parent.queue.put(operation)
                        self.start_operation()
                        return
                    else:
                        self.log_info("Cannot redirect to '%s'" % location)
            # Operation is finished.
            content = bytes(self.body) if self.body is not None else b''
            # Check that request was received in full.
            if self.content_length and len(content) < self.content_length:
                # Did not receive full buffer.
                msg = ("content-length truncated %s/%s" %
                       (len(content), self.content_length))
                self.log_info(msg)
                error = msg if not error else ' - '.join((error, msg))
            if self.transfer_encoding == 'chunked' and not self.chunk_term:
                # Didn't receive chunked terminator.
                self.log_info("Chunked terminator not received")
            # Update operation's cookies with dispatcher's.
            operation.cookies.update(self.cookies)
            operation.finish(code, content, reason, error)
        # Try to start another operation.
        self.start_operation()

    def abort(self, error):
        '''Shutdown connection and abort all queued operations.'''
        self.log_info("abort()")
        # Shutdown self.socket and remove from map, if it exists.
        self.shutdown(block=True)
        # Abort all pending operations.
        while self.op_list:
            operation = self.op_list.pop(0)
            operation.finish(0, content=b"", reason="", error=error)
        if self.operation:
            self.finish_operation(error)
#end class HttpDispatcher(asyncore.dispatcher)



class CfgWebOperation(HttpOperation):
    '''Proxy Operation object to manage CfgWebAPI operations to a host.

    CfgWebOperation(host, command, parameters, path, https=False,
                    queue=None, callback=None, timeout=4.0):

        'host' is the IP address or hostname of the device.
        'command' should be either 'Get' or 'Set'.
        'parameters' is a dictionary of { varId: value } to send.
                     The 'value' is ignored for 'Get' operations.
                     'varId' should be in the format "VVVV@T" where
                             VVVV is the varId and T is the type.
        'path' is normally '/cgi-bin/cfgweb' but can be changed.
               (eg. for FCs maybe '/slot/2/htdocs/cgi-bin/cfgweb' and
                for JSON requests '/cgi-bin/cfgjson').
        'https' can be set to True to use https. Redirects cannot work
                since the values are cleared according to HTTP 1.1.

    The CfgWeb API is the only API for WebEASY versions v1.4 or older.
    It is accessed with HTTP GET requests to URL /cgi-bin/cfgweb
    The query string consists of a command followed by a CSV list of
    parameter VarIDs that are to be retrieved or set. Each parameter
    is in the format "varId@type=value" with the "=value" being omitted
    for Gets.

    The GET reply (new-style) is usually JSON in the format:
    (e.g. 570IPG-3G18-SFPP12 V110B20181204-1687-A)
    '{"result": "success",\n "get": {"1@s": "570IPG-X19-10G",\n"2@s": '
    '"20181025"},\n"time":"1542660934"\n }\n'

    BUT some products return an old-style reply.
    (e.g. 3067VIP10G fw v2.0.0 b20170525-3016 and 3080IPX fw v2.0 b456):
    'GetR&1@s=3067VIP10G-3G-HW+SMPTE+MCR+SM+IN36+OUT4+ENC2,2@s=20180817;'
    'Time&1542660900;'

    The SET reply is usually JSON in the format:
    '{"result": "success",\n "time":"1543429173"\n }\n'
    BUT some legacy products can return a reply like:
    'SetR&OK;'

    Parameter "Get" (case-sensitive) command examples:
        GET /cgi-bin/cfgweb?Get&9150%40s;time&1536240927016
            params = {'9150@s': None}
        GET /cgi-bin/cfgweb?Get&92.0%40i,273%40i,76.0%40s,73.0%40s,71.0%40i,72.0%40i,98.0%40s,191.0%40i,170%40i,174%40i,175%40i,176%40i,198%40i,275%40i,230.0%40i,231.0%40s,232.0%40s,233%40i,235%40i;time&1536240926786
            params = {'92.0@i': None, '273@i': None, ... }
    Parameter "Set" (case-sensitive) command:
        GET /cgi-bin/cfgweb?Set&104.0@i=6,106.0@i=1;time&1536247140001
            params = {'104.0@i': 6, '106.0@i', 1}
        GET /cgi-bin/cfgweb?Set&61.0@s=172.21.1.100,98.0@s=first%20input,233@i=4242;time&1536247626849
            params = {'61.0@s': "172.21.1.100", '98.0@s': "first input", '233@i': 4242}

    Headers can be minimal. Typical headers generated by Firefox:
        Host: IP_ADDRESS
        User-Agent: Mozilla/5.0
        Accept: */*
        Accept-Language: en-US,en;q=0.5
        Accept-Encoding: gzip, deflat
        Referer: http://IP_ADDRESS/page01.php
        X-Requested-With: XMLHttpRequest
        Cookie: PHPSESSID=HASH_VALUE; webeasy-loggedin=true
        Connection: keep-alive

    Attributes:
        self.command = Either 'Get' or 'Set'.
        self.result = Reply parameters (only for 'get').

    Note that sometimes the '@' symbol is URL encoded, but doesn't have
    to be. Also note the malformed ;time&xxx format.
    '''
    def __init__(self, host, command, parameters, path, https=False,
                 queue=None, callback=None, timeout=4.0):
        # Set CfgWebOperation attributes.
        self.command = command.lower()
        self.path = path
        self.result = {}
        if self.command not in ('get', 'set'):
            raise ValueError("Invalid CfgWeb API command '%s'" % command)
        # Build URL
        schema = 'https' if https else 'http'
        URL = "%s://%s%s" % (schema, host, path)
        # Build parameters list for query_string.
        if self.command == 'get':
            csvars = ','.join(varID for varID in parameters)
        else:
            csvars = ','.join("%s=%s" % (varID, quote(str(value)))
                              for varID, value in parameters.items())
        query = "%s&%s;time&%d" % (self.command.title(), csvars, time.time())
        # Call original constructor
        HttpOperation.__init__(self, URL, 'GET', data=None, params=query,
                               headers={}, allow_redirects=False, queue=queue,
                               callback=callback, timeout=timeout)

    def handle_finish(self):
        '''Create self.result if reply was successful.'''
        self.result = {}
        if self.ok is True and not self.error:
            if self.command == 'get':
                # Support for legacy "GetR" replies.
                if self.content.startswith(b"GetR&"):
                    # Ignore GetR and last semicolon. Try to strip time.
                    params, sc, end = self.content[5:-1].rpartition(b';Time')
                    if not params:
                        params = end
                    params = STR(params)
                    # Extract key and values from parameters.
                    kv = [(varid, value.strip()) for varid, equals, value in
                          (csv.partition('=') for csv in params.split(','))
                          if '@' in varid and equals == '=']
                    if kv:
                        ## Generate self.result dictionary from kv list
                        ## trying to convert integer varIDs (@i) to ints.
                        self.result = {key: int(value) if key.endswith('i') and
                                       value.isdigit() else value
                                       for key, value in kv}
                    else:
                        self.error = "Invalid cfgWeb 'GetR' reply"
                        self.ok = False
                else:
                    # Parse 'Get' reply. Should contain JSON parameters.
                    try:
                        ## simplejson 10x faster than json for loading strings
                        ## and in Python2.7 returns str instead of unicode.
                        reply_json = simplejson.loads(
                            self.content, strict=False, encoding='L1')
                    except ValueError as err:
                        self.error = "Unable to parse JSON"
                        self.ok = False
                    else:
                        # Successful parse of JSON. Set self.result.
                        result = reply_json.get('result')
                        if not result or result.lower() != 'success':
                            # If this was a JSON request, let it be.
                            if 'json' in self.path:
                                # /cgi-bin/cfgjson - Result is the JSON body.
                                self.result = reply_json
                            else:
                                # /cgi-bin/cfgweb - Could not find result.
                                self.error = "JSON result %s" % repr(result)
                                self.ok = False
                        params = reply_json.get('get')
                        if params:
                            ## Generate self.result dictionary while
                            ## converting varID to string (?why?) and
                            ## converting integer varID (@i) values to ints.
                            self.result = {
                                str(key): int(value) if key.endswith('i') and
                                value.strip().isdigit() else str(value)
                                for key, value in params.items()}
            else:
                # Legacy 'Set' reply. Should be "SetR&OK;"
                if self.content.startswith(b"SetR&"):
                    if self.content.startswith(b"SetR&OK;"):
                        self.result = {"SetR": "OK"}
                    else:
                        self.error = "Bad set reply: '%s'" % self.content[:40]
                        self.ok = False
                else:
                    # Parse 'Set' reply. Should contain JSON parameters.
                    try:
                        ## simplejson 10x faster than json for loading strings
                        ## and in Python2.7 returns str instead of unicode.
                        reply_json = simplejson.loads(
                            self.content, strict=False, encoding='L1')
                    except ValueError as err:
                        self.error = "Unable to parse JSON"
                        self.ok = False
                    else:
                        # Successful parse of JSON. Set self.result.
                        result = reply_json.get('result')
                        if not result or result.lower() != 'success':
                            self.error = "JSON result %s" % repr(result)
                            self.ok = False
                        self.result = {'result': result}
#end class CfgWebOperation(HttpOperation)



class CfgJsonOperation(HttpOperation):
    '''Proxy Operation object to manage CfgJsonAPI operations to a host.

    CfgJsonOperation(host, body, jsonId, path, version='2.0', https=False,
                     queue=None, callback=None, timeout=4.0, session_id=None)
        'host' is the IP address or hostname of the device.
        'body' is the JSON body to send in the POST.
        'jsonId' is an integer ID that was specified in the body.
                 This is used to validate the response ID is correct.
        'path' is normally '/cgi-bin/cfgjsonrpc' but can be changed.
               eg. for FCs maybe '/slot/2/htdocs/cgi-bin/cfgjsonrpc', or
               for NATX-64 '/v.1.5/php/datas/cfgjsonrpc.php'.
        'version' is the 'jsonrpc' value to send with the request.
        'https' can be set to True to use https. Redirects cannot work
                since the values are cleared according to HTTP 1.1.
        'session_id' is the PHPSESSID cookie value used to authenticate
                     the request. Required for Feb 2020 or newer builds.


    The CfgWeb JSON is supported by all WebEASY v1.5 or later.
    It is accessed with HTTP POST to URL '/cgi-bin/cfgjsonrpc'.
    Also have seen '/v.1.5/php/datas/cfgjsonrpc.php'.

    Starting Feb 2020 'SESSID' and 'webeasy-loggedin' cookies are
    required otherwise 'CGIAuth Request not permitted' will be returned.

    Get HTTP POST Body Example (with extra newlines and spaces):
       {"jsonrpc":"2.0",
        "method":"get",
        "params":{
            "parameters":[{"id":"61.2@s", "type":"string", "name":"IP Address"},
                          {"id":"820.0@s", "type":"string", "name":"SDI Alias"},
                          {"id":"821.0@i", "type":"integer", "name":"SDI Fault Duration"},
                          {"id":"235@i", "type":"integer", "name":"Timeout"},
                          {"id":"233@i", "type":"integer", "name":"Timeout"}]},
        "id":12}
        "username": "root"}     # Added in later versions

    Set HTTP POST Body Example (with extra newlines and spaces):
       {"jsonrpc":"2.0",
        "method":"set",
        "params":{
            "parameters": [{"id":"61.2@s", "type":"string", "name":"IP Address", "value":"192.168.11.55", "value-length":13},
                           {"id":"820.0@s","type":"string","name":"SDI Alias","value":"The Very First","value-length":14},
                           {"id":"821.0@i","type":"integer","name":"SDI Fault Duration","value":555},
                           {"id":"235@i","type":"integer","name":"Timeout","value":42},
                           {"id":"233@i","type":"integer","name":"Timeout","value":4200}]},
        "id":11}

    REPLY:
        {"id":11,
         "jsonrpc":"2.0",
         "result":{
             "parameters":[{"id":"61.2@s","name":"IP Address","type":"string","value":"192.168.11.44"},
                           {"id":"820.0@s","name":"SDI Alias","type":"string","value":"SDI Input !@#$%^&*()"},
                           {"id":"821.0@i","name":"SDI Fault Duration","type":"integer","value":444},
                           {"id":"235@i","name":"Timeout","type":"integer","value":44},
                           {"id":"233@i","name":"Timeout","type":"integer","value":4444}]
                    }
        }
    Failed Reply (note mesasge is spelled wrong):
        {'jsonrpc': '2.0',
         'id': 34020,
         'error': {u'code': -32700, u'mesasge': u'Parsing Error.'}
        }
    Failed second example:
        {"id":6223,
         "jsonrpc":"2.0",
         "error":{"code":-1, "mesasge": "Failed to retrieve data."}
        }
    Another reply with some VarIDs failed:
        {"id":29054,
         "jsonrpc":"2.0",
         "result":{
            "parameters":[{"id":"9","type":"integer","value":3265764309388843077},
                          {"error":{"level":"error","message":"Failed to send request"},"id":"@","type":"integer"},
                          {"error":{"level":"error","message":"IPC Get error"},"id":"s","type":"string"},
                          {"id":"6","type":"integer","value":3265764172015611954}]
                   }
        }
    Failed reply from NATX-style product:
        {"id": 41666
         "jsonrpc": "2.0",
         "error": {"code": 403, "message": "CGI delegate rejects the request - requires one of Basic, Bearer or Session Authentications "},
        }

    Typical headers generated by Firefox (Content-Type is important):
        Host: IPADDRESS
        User-Agent: Mozilla/5.0
        Accept: application/json, text/javascript, */*; q=0.01
        Accept-Language: en-US,en;q=0.5
        Accept-Encoding: gzip, deflate
        Referer: http://IPADDRESS/page01.php
        Content-Type: application/x-www-form-urlencoded; charset=UTF-8
        X-Requested-With: XMLHttpRequest
        Cookie: PHPSESSID=HASH_VALUE; webeasy-loggedin=true
        Connection: keep-alive
    Starting Feb 2020 valid 'PHPSESSID' and 'webeasy-loggedin' values
    are required otherwise 'CGIAuth Request not permitted' is returned.
    Note: This doesn't seem to require a valid login, just a valid ID.

    Attributes:
        self.id = The integer ID sent with the request.
        self.result = Decoded reply JSON parameters as {varId: value}.
    '''
    # Test Reply 1 (cfgWeb) extra \n fails JSON decoding unless strict=False.
    TESTREPLY1 = b'{"result": "success",\n "get": {"3@i": "1",\n"8@s": "7733870043",\n"1@s": "2430RX2-10G+FULL",\n"10@s": "A",\n"9@s": "2409RGBT",\n"2@s": "20151130",\n"6@s": "0045\n",\n"9150@s": "",\n"4@i": "0",\n"11@i": "1"},\n"time":"1540307276"\n }\n'
    # Test Reply 2 spurious \x05 character fails decoding unless strict=False.
    TESTREPLY2 = b'{"result": "success",\n "get": {"204@s": "\x05",\n"3@i": "1",\n"8@s": "7284820013",\n"1@s": "EXE-X-IP18-10GE6",\n"10@s": "A",\n"9@s": "EQX_IP18_IPG",\n"2@s": "20160712",\n"6@s": "1409",\n"4@i": "3",\n"11@i": "1"},\n"time":"1543426585"\n }\n'
    # Test Reply 3 has unicode escape sequences. Requires encoding='L1'.
    TESTREPLY3 = b'{"id":46173,"jsonrpc":"2.0","result":{"parameters":[{"id":"96@s","type":"string","value":"\\u0000\\u0000\\u0000\\u0000\xff\xff\xff\xff\\u000El\xa1\xeb\\f\\n\xa8\xc0\\u0000\\u0000\\u0001\\u0000"}]}}\n'
    # Test Reply 4 has embedded JSON
    TESTREPLY4 = b'{"id":38398,"jsonrpc":"2.0","result":{"parameters":[{"id":"336.534@s","type":"json","value":{"aaData":[["Local","EXE-NCS-0-SC-00","5e:04:95:80:30:17","172.17.141.231","Ethernet Switch Fabric","slot15-31","00:02:c5:1c:af:7f","0.0.0.0",""],["Remote","570IPG","d0:39:72:90:40:e4","172.17.141.16","570IPG-3G18-SFPP12 App I","","00:02:c5:1a:d6:e5","0.0.0.0","eth3"]],"download":false,"iTotalRecords":2,"sColumns":["Local/Remote","Device Name","Device ID","Management IP","Device Description","Port Name","Port ID","Port IP","Port Description"]}}]}}\n'
    # Test Reply 5 has different error reporting.
    TESTREPLY5 = b'{"id":11801,"jsonrpc":"2.0","result":{"parameters":[{"error":{"level":"error","message":"Failed to send request"},"id":"@","type":"integer"},{"id":"3","type":"integer","value":1},{"error":{"level":"error","message":"IPC Get error"},"id":"s","type":"string"}]}}\n'

    def __init__(self, host, body, jsonId, path, https=False, queue=None,
                 callback=None, timeout=4.0, session_id=None):
        # Set CfgWebOperation attributes.
        self.result = {}
        self.id = int(jsonId)
        # Build URL
        schema = 'https' if https else 'http'
        URL = "%s://%s%s" % (schema, host, path)
        # Call original constructor
        content_type = "application/x-www-form-urlencoded; charset=UTF-8"
        headers = {'Content-Type': content_type,
                   'Content-Length': str(len(body)), }
        if session_id:
            headers['Authorization'] = 'Session %s' % session_id
        cookies = {}
        if session_id:
            cookies['PHPSESSID'] = session_id
            cookies['webeasy-loggedin'] = 'true'
        HttpOperation.__init__(self, URL, 'POST', data=body, params=None,
                               headers=headers, allow_redirects=False,
                               callback=callback, queue=queue, timeout=timeout,
                               cookies=cookies)

    def handle_finish(self):
        '''Create self.result if reply was successful.'''
        self.result.clear()
        if self.ok is True and not self.error:
            # Try to parse the JSON reply.
            try:
                ## simplejson is about 10x faster than json for loading strings
                ## and in Python2.7 returns native str instead of unicode.
                reply_json = simplejson.loads(
                    self.content, encoding='L1', strict=False)
            except ValueError as err:
                if b'CGIAuth Request not permitted' in self.content:
                    self.error = 'CGIAuth Request not permitted'
                else:
                    self.error = "Unable to parse JSON content: %s" % str(err)
                    if self.status_code != 200:
                        self.error = "%s - %s" % (self.status, self.error)
                self.ok = False
            else:
                # Make sure the ID matches the request.
                if self.id != reply_json.get('id'):
                    self.ok = False
                    self.error = ("JSON ID %r does not match request ID %r. " %
                                  (repr(reply_json.get('id')), repr(self.id)))
                # Check the JSON result for errors.
                result = reply_json.get('result')
                if result is None:
                    # Try to extract the error message.
                    self.ok = False
                    error = reply_json.get('error')
                    if error:
                        # Message is spelled wrong in many cases.
                        if 'message' in error:
                            message = error['message']
                        elif 'mesasge' in error:
                            message = error['mesasge']
                        else:
                            message = "No result in reply"
                        self.error = STR(message)
                else:
                    # Try to grab parameters from 'result'.
                    parameters = result.get('parameters', None)
                    if parameters is None:
                        self.error = "No parameters in JSON reply"
                        self.ok = False
                    else:
                        for param in parameters:
                            varId = str(param.get('id'))
                            value = param.get('value')
                            error = param.get('error')
                            if error:
                                # Extract error message (could be unicode).
                                if isinstance(error, dict):
                                    message = STR(error.get('message'))
                                else:
                                    message = STR(error)
                                # Append to self.error
                                self.error += "%r-%s" % (varId, message)
                            else:
                                self.result[varId] = value
#end class CfgJsonOperation(HttpOperation)



class CfgJsonInst(object):
    '''A class to manage a large amount of cfgJSON gets from a device.

    Accepts a group of base varIDs as {varId: name} and formats them
    with instance numbers. Returns a reply of (instance: {name: value}).
    The request can be broken up into multiple operations and the
    results are returned per-instance.

    'varIds' should be a dictionary of {varId: key} where each varId
             is in the format "VarID@type" without any instance values.
             The 'key' is any chosen key value to be used in the reply.
                 eg. {'324@s': 'mode', '921@i': 'link'}
    'instances' is a list of instances to grab all the varIds with.
                This is typically a range() object.
    'queue' is the Queue.Queue() object to place the results into.
            Each result is a 2-tuple of ( instance, {key: value, ...} ).
    'packing' defaults to 1600 and is the maximum number of varIDs to
              send per request (1600 keeps each request <65536 bytes).
    'timeout' is the timeout per operation. The entire operation will
              fail if any operation times out.

    The total number of varIDs requested will be:
            len(varIds) * len(instances)

    Will raise ValueError if any baseVarId cannot be formatted with an
    instance number.
    '''
    def __init__(self, thread, host, varIds, instances, queue,
                 packing=None, path='/cgi-bin/cfgjsonrpc', https=False,
                 timeout=None, op_timeout=4.0, version='2.0'):
        # Store base varIDs.
        self.varIds = {}
        for varId, key in varIds.items():
            num, at, typechar = varId.lower().partition('@')
            if num.isdigit() and at == '@' and typechar in 'isj':
                self.varIds[(int(num), typechar)] = key
            else:
                raise ValueError("Invalid varId %s" % varId)
        self.thread = thread
        self.host = host
        self.total = len(instances)
        if not instances or not self.total:
            raise ValueError("Invalid list of instances provided!")
        self.instances = instances
        self.queue = queue
        if packing is None:
            # Calculate packing to limit varIds per request to 1600 or less.
            self.packing = 1600 // len(self.varIds)
        else:
            self.packing = int(packing)
        self.path = path
        self.https = bool(https)
        self.timeout = timeout
        self.op_timeout = float(op_timeout)
        self.version = version
        self.current = 0
        # Start first request
        self.ok = False
        self.finished = False
        self.elapsed = 0
        self.progress = 0
        self.started = time.time()
        self.errors = []
        self.profile = []
        self.send_next()

    def send_next(self):
        '''Send the next request and end the operation if finished.

        May execute in the thread. Operations must be thread-safe.
        '''
        # Are we finished?
        if self.current >= len(self.instances):
            self.finish()
            return
        # Get instance values for next blocks of varIds.
        end = min(self.current + self.packing, len(self.instances))
        instances = (self.instances[i] for i in range(self.current, end))
        varIds = ['%s.%s@%s' % (varid, inst, typechar) for inst in instances
                  for (varid, typechar) in self.varIds]
        #print("Sending request %d-%d (%d)" % (self.current, end, len(varIds)))
        # Schedule the request.
        self.op = self.thread.get_cfgjson(
            self.host, varIds, path=self.path, timeout=self.op_timeout,
            https=self.https, version=self.version, callback=self.callback,
            block=False)
        self.current = end

    def callback(self, op):
        '''Callback for completion of each request.'''
        # Possible the operation finished before this callback was processed.
        if self.finished is True:
            return
        # Process operation
        if op.error:
            self.errors.append(op.error)
        # Process results
        self.profile.append(op.elapsed)
        results = {}
        for varIdstr, value in op.result.items():
            varid, dot, inst = varIdstr.strip().lower().partition('.')
            inst, at, typechar = inst.partition('@')
            if varid.isdigit() and dot == '.' and inst.isdigit():
                varid, inst = int(varid), int(inst)
                key = self.varIds.get((varid, typechar))
                if not key:
                    # JSON hack. Typechar 's' is returned, expected 'j'.
                    key = self.varIds.get((varid, 'j'))
                if key:
                    inst_values = results.get(inst, {})
                    inst_values[key] = value
                    results[inst] = inst_values
                else:
                    self.errors.append("%s@%s unexpected" % (varid, typechar))
        # Check for unhandled error
        if not results and not op.error:
            self.errors.append("No JSON results. Status=%s, body=%s bytes" %
                               (op.status, len(op.content)))
        # Add results to queue.
        for inst in sorted(results):
            self.queue.put((inst, results[inst]))
        # Update progress and elapsed and check for timeout.
        self.progress = int(self.current * 100.0 / max(1, self.total) + 0.5)
        self.elapsed = abs(time.time() - self.started)
        if self.timeout and self.elapsed > self.timeout:
            error = "CfgJsonInst timed out %.1fs" % self.timeout
            self.finish(error)
        else:
            # Schedule next operation.
            self.send_next()

    def finish(self, error=''):
        '''Finish the operation.'''
        self.error = error
        self.ok = True if not error else False
        self.finished = True

    def cancel(self):
        '''Cancel the operation. Will faill with "Cancelled" error message.'''
        self.finish(error="Cancelled")
#end class CfgJsonInst(object)



class CfgWebSafe(object):
    '''A class to manage a large amount of cfgWeb gets from a device.

    Perform a "safe" get of many VarIDs from a cfgWeb host by requesting
    each VarID separately. This works around an issue with cfgWeb where
    the entire request will fail with "500 Internal Server Error" if
    even one VarID is unrecognized.

    'parameters' must be a list of parameters to fetch each one in the
                 format "VarID@type".
    'timeout' is the overall timeout for the entire operation.

    While the operation is ongoing the following atrributes are updated:
    self.elapsed = Time taken for the operation.
    self.progress = Percent (0-100) completion of the operation.
    self.finished = True when operation has completed or timed out.

    When self.finished is set to True, these attributes are populated:
    self.ok = True if operation was successful, False otherwise.
    self.error = Error text is self.ok is False, otherwise blank string.
    self.result = Dictionary of { VarID: Value }. May be empty.
    '''
    def __init__(self, thread, host, parameters, path='/cgi-bin/cfgweb',
                 timeout=4.0, https=False, queue=None, callback=None):
        # Store varIDs.
        self.thread = thread
        self.host = host
        self.parameters = parameters
        self.path = path
        self.timeout = float(timeout)
        self.https = bool(https)
        self.queue = queue
        self.callback = callback
        # Setup internal attributes.
        self.total = len(parameters)
        self.result = {}
        self.started = time.time()
        self.elapsed = 0
        self.current = 0
        self.progress = 0
        self.ok = False
        self.finished = False
        self.errors = []
        # Start first request
        self.send_next()

    def send_next(self):
        '''Send the next request and end the operation if finished.

        May execute in the thread. Operations must be thread-safe.
        '''
        # Are we finished?
        if self.current >= self.total:
            self.finish()
            return
        # Schedule the request for the next VarID.
        varID = self.parameters[self.current]
        self.current += 1
        time_left = max(0.1, self.timeout - abs(time.time() - self.started))
        #print("CfgWebSafe: Next=%s, time_left=%.1f" % (varID, time_left))
        self.op = self.thread.get_cfgweb(
            self.host, [varID], path=self.path, timeout=time_left,
            https=self.https, callback=self.internal_callback, block=False)

    def internal_callback(self, op):
        '''Internal callback for completion of each request.'''
        # Possible the operation finished before this callback was processed.
        if self.finished is True:
            return
        # Process operation
        if op.error:
            self.errors.append(op.error)
        self.result.update(op.result)
        # Update progress and elapsed and check for timeout.
        self.progress = int(self.current * 100.0 / max(1, self.total) + 0.5)
        self.elapsed = abs(time.time() - self.started)
        if self.elapsed > self.timeout:
            error = "CfgWebSafe timed out %.1fs" % self.timeout
            self.finish(error)
        else:
            # Schedule next operation.
            self.send_next()

    def finish(self, error=''):
        '''Finish the operation.'''
        # Did any errors occur? Ignore "500 Internal Server Error" for cfgWeb.
        self.error = error
        if not self.error:
            # Scan self.errors for any serious error.
            for error in self.errors:
                if '500' not in error:
                    self.error = error
                    break
        self.ok = True if not self.error else False
        self.finished = True
        # Add ourselves to the caller's queue, if one was specified.
        if self.queue:
            self.queue.put(self)
        # Call the callback function, if specified.
        if callable(self.callback):
            try:
                self.callback(self)
            except Exception as err:
                if self.error:
                    self.error += " - "
                self.error = self.error + "Callback exception: %s" % str(err)
                traceback.print_exc()

    def cancel(self):
        '''Cancel the operation. Will faill with "Cancelled" error message.'''
        self.finish(error="Cancelled")
#end class CfgWebSafe(object)



class CfgJsonAuth(object):
    '''A class to manage a cfgJson request with login/authentication.

    Starting in Feb 2020 cfgJSON requests will fail unless there is an
    associated 'PHPSESSID' and 'webeasy-loggedin' cookies. What's ironic
    is that a login doesn't even need to be successful, as long as the
    session ID is valid.

    First attempts a regular fetch of cfgJSON parameters. If the result
    is 'CGIAuth Request not permitted', then it will attempt to login
    to the device with the given 'username' and 'password', and then
    retry the request. There is only one attempted retry.

    'parameters' must be a list of parameters to fetch each one in the
                 format "VarID@type".
    'timeout' is the overall timeout for the entire operation.

    While the operation is ongoing the following atrributes are updated:
    self.elapsed = Time taken for the operation.
    self.progress = Percent (0-100) completion of the operation.
    self.finished = True when operation has completed or timed out.
    self.session_id = `None` or the PHPSESSID cookie from logging in.

    When self.finished is set to True, these attributes are populated:
    self.ok = True if operation was successful, False otherwise.
    self.error = Error text is self.ok is False, otherwise blank string.
    self.result = Dictionary of { VarID: Value }. May be empty.
    '''
    def __init__(self, thread, host, body, jsonId, path, https=False,
                 queue=None, callback=None, timeout=4.0, username='root',
                 password='evertz'):
        # Store varIDs.
        self.thread = thread
        self.host = host
        self.body = body
        self.jsonId = jsonId
        self.path = path
        self.https = bool(https)
        self.queue = queue
        self.callback = callback
        self.timeout = float(timeout)
        self.username = username
        self.password = password
        # Setup internal attributes.
        self.result = {}
        self.started = time.time()
        self.elapsed = 0
        self.current = 0
        self.progress = 0
        self.ok = False
        self.finished = False
        self.error = ""
        self.session_id = None
        # Need to clone these attributes to mimic an HttpOperation
        self.sent = 0
        self.active = False
        self.status = None
        self.status_code = 0
        self.reason = ""
        self.headers = {}
        self.content = ""
        self.url = ""
        self.num_redirects = 0
        # Start first request
        self.attempt = 0
        self.send_next()

    def send_next(self):
        '''Send the next request and end the operation if finished.

        May execute in the thread. Operations must be thread-safe.
        '''
        # Compute how much time left until timeout
        time_left = max(0.1, self.timeout - abs(time.time() - self.started))
        self.active = True
        self.scheme = 'https' if self.https else 'http'
        if self.thread.is_alive() is False:
            self.finish("HTTP thread died")
        # Schedule the next operation.
        if self.attempt == 0 or self.attempt == 3:
            # Initial or final cfgJSON fetch attempt.
            self.op = CfgJsonOperation(
                self.host, self.body, self.jsonId, self.path, https=self.https,
                callback=self.internal_callback, timeout=time_left,
                session_id=self.session_id)
            self.thread.queue.put(self.op)
        elif self.attempt == 1:
            # First attempt failed. Go to login page to get cookie.
            self.url = "%s://%s/login.php" % (self.scheme, self.host)
            self.op = self.thread.get(
                self.url, allow_redirects=False, block=False,
                callback=self.internal_callback, timeout=time_left)
        elif self.attempt == 2:
            # Second attempt, now we login (not even necessary).
            self.url = "%s://%s/login.php" % (self.scheme, self.host)
            form = {'user': self.username, 'password': self.password,
                    'query': "location=aHR0cDovLzE3Mi4xNy4xNTYuMjAv",
                    'location': "%s://%s/" % (self.scheme, self.host),
                    'SubmitPassword': 'Login'}
            self.op = self.thread.post(
                self.url, data=form, allow_redirects=False, block=False,
                callback=self.internal_callback, timeout=time_left)
        # Copy attributes from self.op to fully mimic HTTPOperation.
        if self.op:
            self.req_url = self.op.req_url
            self.req_headers = self.op.req_headers
            self.cookies = self.op.cookies

    def internal_callback(self, op):
        '''Internal callback for completion of each request.'''
        #print("cfgJsonAuth.callback(%r=%r,%r,%r/%r)" % (op.url, op.ok, op.status, op.num_redirects,op.max_redirects))
        # Possible the operation finished before this callback was processed.
        if self.finished is True:
            return
        # Update progress, elapsed, and HTTPOperation attributes.
        self.progress = min((self.attempt + 1) * 25, 99)
        self.elapsed = abs(time.time() - self.started)
        self.sent += op.sent
        self.status = op.status
        self.status_code = op.status_code
        self.reason = op.reason
        self.headers = op.headers
        self.content = op.content
        self.url = op.url
        self.num_redirects = op.num_redirects
        # Extract any result from the operation (CfgJsonOperations only).
        if hasattr(op, 'result'):
            self.result = op.result
        # Extract PHP session ID cookie, if it exists.
        php_session_id = op.cookies.get('PHPSESSID')
        if php_session_id:
            self.session_id = php_session_id
        # Check for timeout, error and completion.
        if self.elapsed > self.timeout:
            # We timed out. Fail operation.
            error = "CfgJsonAuth timed out %.1fs" % self.timeout
            self.finish(error=error)
            return
        if self.attempt == 0:
            # First operation. Was it successful?
            if op.error:
                # No. Was it a CGIAuth failure?
                if 'CGIAuth' in op.error or 'CGI delegate' in op.error:
                    # Continue to next request to try to login.
                    self.attempt += 1
                # Was it a non-JSON fatal error?
                elif ('Unable to parse JSON' in op.error and
                      b'Fatal error' in op.content):
                    # Continue to next request to try to login.
                    self.attempt += 1
                else:
                    # A real error occured. End operation.
                    self.finish(error=op.error)
                    return
            else:
                # Success on the first try!
                self.finish()
                return
        else:
            # Still grinding through attempts. Did we fail/succeed?
            if op.error:
                # Any failure we end the operation.
                self.finish(error=op.error)
                return
            self.attempt += 1
            if self.attempt > 3:
                # Success!
                self.finish()
                return
        # Send next request.
        self.send_next()

    def finish(self, error=''):
        '''Finish the operation.'''
        #print("cfgJsonAuth.finish(%s)" % repr(error))
        # Did any errors occur? Ignore "500 Internal Server Error" for cfgWeb.
        self.error = error
        ## Mimick cfgJsonOperation here, where operation may have been ok
        ## but errors were added to self.errors
        self.ok = True if self.result or not self.error else False
        self.finished = True
        # Add ourselves to the caller's queue, if one was specified.
        if self.queue:
            self.queue.put(self)
        # Call the callback function, if specified.
        if callable(self.callback):
            try:
                self.callback(self)
            except Exception as err:
                if self.error:
                    self.error += " - "
                self.error = self.error + "Callback exception: %s" % str(err)
                traceback.print_exc()

    def cancel(self):
        '''Cancel the operation. Will faill with "Cancelled" error message.'''
        self.finish(error="Cancelled")
#end class CfgJsonAuth(object)



class HttpThread(threading.Thread):
    '''Thread to perform HTTP operations.

        HttpThread(iface='', debug=0)
    '''
    # Dispatcher Timeout in seconds.
    DISPATCHER_TIMEOUT = 120    # 2 minutes
    # CPU throttle when thread is active (polls/10ms).
    THROTTLE = 200
    # self.loglist maximum size (in messages).
    LOGSIZE = 1024

    def __init__(self, **kwargs):
        # Grab keyword arguments.
        self.debug = int(kwargs.pop('debug', 0))
        self.iface = kwargs.pop('iface', '')
        # Call original constructor (will complain if extra kwargs present).
        threading.Thread.__init__(self, **kwargs)
        # Record parent thread (the one that creates this object).
        self.parent = threading.current_thread()
        # Initialize attributes
        self.status = "Stopped"             # Current thread status.
        self.endEvent = threading.Event()   # End event.
        self.queue = Queue.Queue()          # queue of Operation() objects.
        self.logmutex = threading.Lock()    # Mutex for loglist.
        self.loglist = []                   # List of log messages.
        self.idle = True                    # All operations complete.
        self.ticks = 0

    def run(self):
        '''This is the method that executes in a separate thread.'''
        self.endEvent.clear()
        self.status = "Starting"
        self.log(self.status)
        # Dictionary of { address: dispatcher }
        connections = {}
        # Dictionary of { socket: dispatcher } used by asyncore.
        socket_map = {}
        # Run main thread loop until signalled to exit.
        thread_error = ""
        last_tick = self.ticks
        while self.endEvent.is_set() is False:
            self.ticks += 1
            #1. Grab operations from the Queue and connect them.
            while self.endEvent.is_set() is False:
                try:
                    operation = self.queue.get_nowait()
                except Queue.Empty:
                    break
                else:
                    # Do we have a dispatcher for this host?
                    if operation.address in connections:
                        dispatcher = connections.get(operation.address)
                    else:
                        # Create new dispatcher.
                        dispatcher = HttpDispatcher(self,socket_map,self.debug)
                        connections[operation.address] = dispatcher
                    # Add this operation to the dispatcher's queue.
                    dispatcher.add_operation(operation)

            #2. Run the asyncore event loop once (will wait max 100ms).
            if self.endEvent.is_set() is False:
                # Try to stay within Windows select() limit of 512 sockets.
                if len(socket_map) > 512:
                    wait_map = dict(list(socket_map.items())[:512])
                else:
                    wait_map = socket_map
                try:
                    asyncore.loop(map=wait_map, count=1, timeout=0.100)
                except ValueError as err:
                    # Too many sockets for select().
                    self.log(str(err))

            #3. Poll all HttpDispatchers and get activity.
            last_active = 0
            for address, dispatcher in list(connections.items()):
                active = dispatcher.poll()
                last_active = max(last_active, active)
                if abs(time.time() - active) > self.DISPATCHER_TIMEOUT:
                    # Dispatcher has timed out. Can we shut it down?
                    if not dispatcher.operation:
                        #print("HTTPDispatcher %s timed out" % repr(address))
                        self.log("HTTPDispatcher %s timed out" % repr(address))
                        dispatcher.shutdown(block=True)
                        connections.pop(address)

            #4. Set thread status
            idle = abs(time.time() - last_active)
            idle_time = "Idle," if idle >= 10 else ("Idle=%.1f," % idle)
            self.status = ("%s Map=%s, ticks=%s" % (idle_time, len(socket_map),
                                                    format(self.ticks, ',')))
            if idle < 0.1:
                # Thread is active. Perform minimum sleep (10ms on Windows).
                time.sleep(0.010)
                if (self.ticks - last_tick) > self.THROTTLE:
                    #time.sleep(0.010)
                    last_tick = self.ticks
            else:
                # Thread is idle. Sleep it so we don't thrash the CPU.
                last_tick = 0
                #self.status = "%.3fs idle" % idle
                time.sleep(0.1)

            #5. End thread loop if parent thread has ended.
            if self.parent.is_alive() is False:
                thread_error = "Parent thread died"
                break
        # Exited thread main loop. Close all open connections.
        self.log("HttpThread exited main loop. Closing connections")
        if thread_error:
            self.status = "HttpThread exited due to error: %s" % thread_error
        else:
            self.status = "HttpThread exited normally"
        for address, dispatcher in connections.items():
            dispatcher.abort(self.status)
        self.log(self.status)
        self.log("Exited socket_map=%s" % repr(socket_map))

    def log(self, message):
        '''Add message to loglist with timestamp, preventing duplicates.

        Must be thread-safe since this is called by child threads.
        '''
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
            pass
            print(message)

    def stop(self, block=True):
        '''Signal thread to shutdown and optionally block until it does.'''
        self.endEvent.set()
        if block is True:
            self.join()

    def get(self, URL, params=None, headers={}, files=None, safe=',',
            allow_redirects=True, max_redirects=2, queue=None, callback=None,
            timeout=4.0, auth=None, cookies={}, block=True):
        '''Schedule an HTTP GET operation for the given URL.

        May raise ValueError on an invalid URL, params, or headers.
        If block is True, will block until the operation is complete and
        the 'queue' and 'callback' arguments are ignored.
        Returns the HttpOperation() object that is queued.
        '''
        return self.request('GET', URL, data=None, params=params, files=files,
                            queue=queue, headers=headers, safe=safe,
                            allow_redirects=allow_redirects, cookies=cookies,
                            max_redirects=max_redirects, auth=auth,
                            callback=callback, timeout=timeout, block=block)

    def post(self, URL, data=None, params=None, files=None, headers={},
             safe=',', allow_redirects=True, max_redirects=2, queue=None,
             callback=None, auth=None, cookies={}, timeout=4.0, block=True):
        '''Schedule an HTTP GET operation for the given URL.

        May raise ValueError on an invalid URL, params, or headers.
        If block is True, will block until the operation is complete and
        the 'queue' and 'callback' arguments are ignored.
        Returns the HttpOperation() object that is queued.
        '''
        # Create operation and add to queue.
        return self.request('POST', URL, data=data, params=params, files=files,
                            queue=queue, headers=headers, safe=safe,
                            allow_redirects=allow_redirects, cookies=cookies,
                            max_redirects=max_redirects, auth=auth,
                            callback=callback, timeout=timeout, block=block)

    def request(self, method, URL, data=None, params=None, files=None,
                headers={}, safe=',', auth=None, allow_redirects=True,
                max_redirects=2, queue=None, callback=None, timeout=4.0,
                cookies={}, block=True):
        '''Schedule an HTTP request using the method for the given URL.'''
        if self.is_alive() is False:
            raise RuntimeError("Cannot perform %s: Thread not running" % method)
        if block is True:
            if queue is not None:
                raise ValueError("queue invalid for blocking operation")
            if callback is not None:
                raise ValueError("callback invalid for blocking operation")
            queue = Queue.Queue()
        # Create operation and add to queue.
        operation = HttpOperation(URL, method, data=data, params=params,
                                  files=files, headers=headers, safe=safe,
                                  allow_redirects=allow_redirects, auth=auth,
                                  max_redirects=max_redirects, queue=queue,
                                  timeout=timeout, cookies=cookies,
                                  callback=callback)
        self.queue.put(operation)
        if block is True:
            try:
                queue.get(block=True, timeout=timeout + 1.0)
            except Queue.Empty:
                pass
        return operation

    # CfgWebAPI Methods ------------------------------------------------
    def get_cfgweb(self, host, parameters, path='/cgi-bin/cfgweb', timeout=4.0,
                   https=False, queue=None, callback=None, block=True):
        '''Do a CfgWebAPI 'Get' to the host for the given parameters.

        'parameters' must be a list of parameters to fetch each one in
        the format "VarID@type". Returns an operation object which will
        contain the reply values in the 'result' attribute.

        Note: cfgWeb is an older, crappier API where the entire request
              will fail if a single VarID is unrecognized. Because of
              this is is better to use the get_cfgweb_safe() method.
        '''
        # Perform CfgWeb API Request
        parameters = {param: None for param in parameters}
        return self.request_cfgweb(host, 'Get', parameters, path,
                                   timeout=timeout, https=https, block=block,
                                   queue=queue, callback=callback)

    def set_cfgweb(self, host, parameters, path='/cgi-bin/cfgweb', timeout=4.0,
                   https=False, queue=None, callback=None, block=True):
        '''Do a CfgWebAPI 'Set' to the host for the given parameters.

        'parameters' must be a dictionary of parameters and the values
        to set each one to in the format {"VarID@type": value}.
        Returns an operation object which will contain the reply values
        in the 'result' attribute.
        '''
        # Perform CfgWeb API Request
        return self.request_cfgweb(host, 'Set', parameters, path,
                                   timeout=timeout, https=https, block=block,
                                   queue=queue, callback=callback)

    def request_cfgweb(self, host, command, parameters, path, timeout=4.0,
                       https=False, queue=None, callback=None, block=True):
        '''Schedule a CfgWeb API request for the given parameters.'''
        if self.is_alive() is False:
            raise RuntimeError("Cannot perform CfgWebGET - Thread not running")
        if block is True:
            if callback is not None:
                raise ValueError("callback invalid for blocking operation")
            queue = Queue.Queue()
        # Create operation and add to queue.
        operation = CfgWebOperation(host, command, parameters, path,
                                    https=https, queue=queue,
                                    callback=callback, timeout=timeout)
        self.queue.put(operation)
        if block is True:
            try:
                queue.get(block=True, timeout=timeout + 1.0)
            except Queue.Empty:
                pass
        return operation

    def get_cfgweb_safe(self, host, parameters, path='/cgi-bin/cfgweb',
                        timeout=4.0, https=False, queue=None, callback=None,
                        block=True):
        '''Do a safe CfgWebAPI 'Get' to the host for multiple parameters.

        'parameters' must be a list of parameters to fetch each one in
        the format "VarID@type". Returns an operation object which will
        contain the reply values in the 'result' attribute.
        '''
        operation = CfgWebSafe(self, host, parameters, path=path, https=https,
                               timeout=timeout, queue=queue, callback=callback)
        if block is True:
            while not operation.finished:
                time.sleep(0.1)
        return operation


    # CfgJSON API Methods ----------------------------------------------
    def get_cfgjson(self, host, parameters, path='/cgi-bin/cfgjsonrpc',
                    version='2.0', jsonId=None, https=False, queue=None,
                    callback=None, timeout=4.0, block=True, username='root',
                    password='evertz'):
        '''Do a CfgJsonRPC 'get' from the host for the given parameters.

        'parameters' must be a list or generator of varIDs to fetch,
        each one in the format "VarID@type", where 'type' can be one of
        's' (string), 'i' (integer), or 'j' (JSON hack).
        JSON hack means we request a string with "type" set to JSON.
        Can also be a dictionary with varID keys (values are ignored).

        Returns an operation object which will contain the reply values
        in the 'result' attribute.
        '''
        # Manual generation of JSON body to side-step json.dumps slowness.
        CFGJSON_BODY = ('{"params": {"parameters": [%s]}, "jsonrpc": "%s", '
                        '"method": "%s", "id": %s}')#, "username": "root"}')
        CFGJSON_INT = '{"type": "integer", "id": "%s"}'
        CFGJSON_STR = '{"type": "string", "id": "%s"}'
        CFGJSON_JSON = '{"type": "json", "id": "%ss"}'
        # parameters must be a list of dictionary of varIds.
        if not hasattr(parameters, '__iter__'):
            raise ValueError("parameters should be a list of VarID strings")
        # Generate unique ID for request, if one wasn't specified.
        if jsonId is None:
            jsonId = random.randint(1,65535)
        else:
            jsonId = int(jsonId)
        # Build cfgJSON request body string manually (faster than json.dumps).
        params = (CFGJSON_INT % varid if varid[-1] == 'i' else
                  (CFGJSON_JSON % varid[:-1] if varid[-1] == 'j' else
                   CFGJSON_STR % varid) for varid in parameters)
        body = CFGJSON_BODY % (', '.join(params), version, 'get', jsonId)
        # Create and send cfgJSON HTTP POST request.
        return self.request_cfgjson(host, body, jsonId, path, queue=queue,
                                    https=https, timeout=timeout, block=block,
                                    callback=callback, username=username,
                                    password=password)

    def set_cfgjson(self, host, parameters, path='/cgi-bin/cfgjsonrpc',
                    version='2.0', jsonId=None, https=False, queue=None,
                    callback=None, timeout=4.0, block=True, username='root',
                    password='evertz'):
        '''Do a CfgJsonRPC 'set' to the host for the given parameters.

        'parameters' is a dictionary of { varId: value } to send.
                     'varId' should be in the format "VVVV@T" where
                             VVVV is the varId and T is the type.
                             The types supported are:
                             's' = string
                             'i' = integer
                             'j' = JSON (hack, will return 's')

        Returns an operation object which will contain the reply values
        in the 'result' attribute.
        '''
        # Generate unique ID for request, if one wasn't specified.
        if jsonId is None:
            jsonId = random.randint(1,65535)
        else:
            jsonId = int(jsonId)
        # Build JSON SET parameter list.
        jsonParams = []
        for varId, value in parameters.items():
            if value is None:
                continue
            if varId.endswith('s'):
                # String type
                item = {'id': varId, 'type': 'string', 'value': value,
                        'value-length': len(value)}
            elif varId.endswith('j'):
                # Hack to add JSON type. VarId = @s, type='json'.
                item = {'id': varId[:-1]+'s', 'type': "json", 'value': value,
                        'value-length': len(value)}
            else:
                # Integer type
                ## Note: Do not convert number value to string. IPG PTP
                ##       reset (868@i) needs a number to work properly.
                item = {'id': varId, 'type': "integer", 'value': value}
            jsonParams.append(item)
        # Combine parameters into JSON and convert to JSON request body string.
        jsonrpc = {"jsonrpc": version, "method": 'set', "id": jsonId,
                   "params": {'parameters': jsonParams}}
        body = json.dumps(jsonrpc)
        # Perform CfgJSON RPC Request
        return self.request_cfgjson(host, body, jsonId, path, queue=queue,
                                    https=https, timeout=timeout, block=block,
                                    callback=callback, username=username,
                                    password=password)

    def request_cfgjson(self, host, body, jsonId, path, https=False,
                        queue=None, callback=None, timeout=4.0, block=True,
                        username='root', password='evertz'):
        '''Schedule a CfgJSON RPC POST request for the given body.

        'body' is the JSON string of the POST containing the request.
        'jsonId' is the integer ID to uniquely identify the request.
        '''
        if self.is_alive() is False:
            raise RuntimeError("Cannot perform CfgJSON - Thread not running")
        if block is True:
            if callback is not None:
                raise ValueError("callback invalid for blocking operation")
            queue = Queue.Queue()
        # Create CfgJsonAuth and pass reference to this thread.
        operation = CfgJsonAuth(self, host, body, jsonId, path, https=https,
                                queue=queue, callback=callback,
                                timeout=timeout, username=username,
                                password=password)
        if block is True:
            try:
                queue.get(block=True, timeout=timeout + 1.0)
            except Queue.Empty:
                pass
        return operation

    def get_cfgjson_inst(self, host, parameters, instances, packing=None,
                         path='/cgi-bin/cfgjsonrpc', queue=None, version='2.0',
                         https=False, timeout=None, op_timeout=4, block=True):
        '''Do a CfgJsonRPC get of the 'parameters' for all 'instances'.

        'parameters' must be a dictionary of { varID : name }.
        'instances' should be a list of all instances with which to grab
        all the varIDs with (eg. a range() object). These values are
        stamped right after the varID number. This can also be a list of
        strings in the format "n.n" for multiple instance values per ID.

        Every instance is requested by stamping all varIDs with the
        instance number and adding to the request. This means that
        len(parameters) * len(instances) varIDs are requested in total.

        Returns a CfgJsonInst() object. The results are appended to the
        queue as 2-tuples: (instance, {name: value}).

        The 'packing' parameter specifies how many instances to pack
        into each request. If `None` this is automatically set so that
        each request has a maximum of 1600 varIDs.
        '''
        if queue is None:
            queue = Queue.Queue()
        operation = CfgJsonInst(self, host, parameters, instances, queue,
                                path=path, packing=packing, version=version,
                                https=https, timeout=timeout,
                                op_timeout=op_timeout)
        if block is True:
            while not operation.finished:
                time.sleep(0.1)
        return operation
#end class HttpThread(threading.Thread)


def start(**kwargs):
    """Return a new, started and running HttpThread instance."""
    thread = HttpThread(**kwargs)
    thread.start()
    return thread

# Some simple self-tests if this module is run as a program.
if __name__ == "__main__":
    import sys              # Python system
    import struct           # Packed 32-bit IP operations
    import argparse         # GNU-style argument parsing

    # Create and configure argument parser.
##    description = ("Perform mass HTTP get on an entire subnet.")
##    epilog = "Report bugs to cbeytas@evertz.com"
##    parser = argparse.ArgumentParser(description=description, epilog=epilog)
##    parser.add_argument('IP', metavar="SUBNET",
##                        help="IP Address of subnet to scan.")
##    parser.add_argument('-v', '--verbose', action='store_true', dest='debug',
##                        default=0, help="Increased verbosity (debug output)")
##    # Parse arguments into args object.
##    args = parser.parse_args()
##    try:
##        subnet = struct.unpack("!L", socket.inet_aton(args.IP))[0] & 0xFFFFFF00
##    except (socket.error, struct.error) as err:
##        print("Invalid subnet IP '%s'" % args.IP)
##        sys.exit(1)
##
##    subnetIP = ".".join(str((subnet >> i) & 0xFF) for i in (24,16,8,0))
##    print("Scanning subnet %s..." % subnetIP)
##    IPs = ["172.17.157.18","172.17.157.19","172.17.157.20","172.17.157.21",
##           "172.17.157.22","172.17.157.23","172.17.157.24",]
##    # Start thread and schedule GETs.
##    varids = ['1@s', '2@s', '3@i', '4@i', '6@s','8@s', '9@s', '10@s', '11@i',
##              '20@s', '9150@s']

    http = HttpThread(debug=True)
    http.start()
    #sys.exit(0)

    parameters = ('349@i',)
    op = http.get_cfgjson("172.17.152.196", parameters=parameters)
    print("Error=%r, result=%r" % (op.error, op.result))
    sys.exit(0)

    parameters = ('9150@s', '338.0@s', '339.0@s')
    op = http.get_cfgjson("172.17.141.231", parameters=parameters,
                            username='admin')
    print("Operation ok=%s (%s) in %.3fs" % (op.ok, op.status, op.elapsed))
    if op.error:
        print(op.error)
        print(repr(op.content))
    else:
        print("Success!")
        print(op.result)

    # POSTing a config to a Magnum client-host using simple authentication.
    op = http.post("http://172.17.235.199/magnum/admin/import_config",
                     auth=("admin", "admin"), timeout=20,
                     files={"file": open("C:\\temp\\Magnum-ClientHost-2018-06-28_05_55_21_magnum_config.zf", 'rb')})

    # POSTing a web-socket call to a Magnum using simple authentication.
    op = http.post("http://172.17.141.251/magnum/ws/login",
                   files={'params': '{"username":"admin", "password":"admin"}'})

    # Very strange device ProGuard Control Panel (172.17.125.43) very slow.

    # Lots of system-rescue images at 172.16.187.x

    # evMV-VIP 172.17.160.108, 172.17.207.102
    # NATx at 172.17.217.197
    # DF9 at 172.17.219.165

    # Bad ASCII character in 172.16.126.* - Line 4743 UnicodeDecodeError 'ascii' codec
##
##    def cbfunc(opt):
##        data = {'user':'admin','password':'admin','SubmitPassword':'Login'}
##        http.post("http://%s/login.php" % opt.address[0], data=data, block=False)
##        http.get("http://%s/v.1.5/php/features/feature-transfer-download.php?filename=570ipg_config.json" % opt.address[0],
##                             block=False)
##        print("cffunc")
##
##    ops = []
##    for IP in IPs:
##        ops.append(http.get_cfgweb(IP, parameters=varids, block=False))
##        ops.append(http.get("http://%s/version.txt" % IP, block=False,
##                              callback=cbfunc))
##    ops.append(http.get("http://www.reddit.com", block=False, timeout=10))
##    ops.append(http.get("http://www.ebay.com", block=False, timeout=10))
##    ops.append(http.get("http://www.google.com", block=False))
##    ops.append(http.get("http://www.google.com",))
##                    #headers={'Connection': 'keep-alive'})
##    count = 0
##    while not all(op.finished for op in ops) and http.is_alive() is True:
##        if count % 10 == 0:
##            print(http.status)
##        time.sleep(0.1)
##        count += 1

    # Clean up
    http.stop()
    print("End of line")
    sys.exit(0)
