# Copyright (C) 2013, Red Hat, Inc.
# All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import os
import struct

from kdcproxy.exceptions import ParsingError

ASN1MOD = os.environ.get('KDCPROXY_ASN1MOD')

if ASN1MOD is None:
    try:
        from asn1crypto.version import __version_info__ as asn1crypto_version
    except ImportError:
        asn1crypto_version = None
    else:
        if asn1crypto_version >= (0, 22, 0):
            ASN1MOD = 'asn1crypto'
    if ASN1MOD is None:
        try:
            __import__('pyasn1')
        except ImportError:
            pass
        else:
            ASN1MOD = 'pyasn1'

if ASN1MOD == 'asn1crypto':
    from kdcproxy import parse_asn1crypto as asn1mod
elif ASN1MOD == 'pyasn1':
    from kdcproxy import parse_pyasn1 as asn1mod
else:
    raise ValueError("Invalid KDCPROXY_ASN1MOD='{}'".format(ASN1MOD))


class ProxyRequest(object):
    TYPE = None
    OFFSET = 4

    @classmethod
    def parse(cls, data):
        request, realm, _ = asn1mod.decode_proxymessage(data)

        # Check the length of the whole request message.
        (length, ) = struct.unpack("!I", request[0:4])
        if length + 4 != len(request):
            raise ParsingError("Invalid request length.")

        for subcls in cls.__subclasses__():
            try:
                return subcls.parse_request(realm, request)
            except ParsingError:
                pass

        raise ParsingError("Invalid request.")

    @classmethod
    def parse_request(cls, realm, request):
        pretty_name = asn1mod.try_decode(request[cls.OFFSET:], cls.TYPE)
        return cls(realm, request, pretty_name)

    def __init__(self, realm, request, pretty_name):
        self.realm = realm
        self.request = request
        self.pretty_name = pretty_name

    def __str__(self):
        return "%s %s (%d bytes)" % (self.realm, self.pretty_name,
                                     len(self.request) - 4)


class TGSProxyRequest(ProxyRequest):
    TYPE = asn1mod.TGSREQ


class ASProxyRequest(ProxyRequest):
    TYPE = asn1mod.ASREQ


class KPASSWDProxyRequest(ProxyRequest):
    TYPE = asn1mod.APREQ
    OFFSET = 10

    @classmethod
    def parse_request(cls, realm, request):
        # Check the length count in the password change request, assuming it
        # actually is a password change request.  It should be the length of
        # the rest of the request, including itself.
        (length, ) = struct.unpack("!H", request[4:6])
        if length != len(request) - 4:
            raise ParsingError("Parsing the KPASSWD request length failed.")

        # Check the version number in the password change request, assuming it
        # actually is a password change request.  Officially we support version
        # 1, but 0xff80 is used for set-password, so try to accept that, too.
        (version, ) = struct.unpack("!H", request[6:8])
        if version != 0x0001 and version != 0xff80:
            raise ParsingError("The KPASSWD request is an incorrect version.")

        # Read the length of the AP-REQ part of the change request.  There
        # should be at least that may bytes following this length, since the
        # rest of the request is the KRB-PRIV message.
        (length, ) = struct.unpack("!H", request[8:10])
        if length > len(request) - 10:
            raise ParsingError("The KPASSWD request appears to be truncated.")

        # See if the tag looks like an AP request, which would look like the
        # start of a password change request. The rest of it should be a
        # KRB-PRIV message.
        asn1mod.try_decode(request[10:length + 10], asn1mod.APREQ)
        asn1mod.try_decode(request[length + 10:], asn1mod.KRBPriv)

        self = cls(realm, request, "KPASSWD-REQ")
        self.version = version
        return self

    def __str__(self):
        tmp = super(KPASSWDProxyRequest, self).__str__()
        tmp += " (version 0x%04x)" % self.version
        return tmp


def decode(data):
    return ProxyRequest.parse(data)


def encode(data):
    return asn1mod.encode_proxymessage(data)
