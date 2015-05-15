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

import struct

from pyasn1 import error
from pyasn1.codec.der import decoder, encoder

import kdcproxy.asn1 as asn1


class ParsingError(Exception):

    def __init__(self, message):
        super(ParsingError, self).__init__(message)
        self.message = message


class ProxyRequest(object):
    TYPE = None
    OFFSET = 4

    @classmethod
    def parse(cls, data):
        (req, err) = decoder.decode(data, asn1Spec=asn1.ProxyMessage())
        if err:
            raise ParsingError("Invalid request.")

        request = req.getComponentByName('message').asOctets()
        realm = req.getComponentByName('realm').asOctets()
        try:  # Python 3.x
            realm = str(realm, "UTF8")
        except TypeError:  # Python 2.x
            realm = str(realm)

        # Check the length of the whole request message.
        (length, ) = struct.unpack("!I", request[0:4])
        if length + 4 != len(request):
            raise ParsingError("Invalid request length.")

        for subcls in cls.__subclasses__():
            try:
                (req, err) = decoder.decode(request[subcls.OFFSET:],
                                            asn1Spec=subcls.TYPE())
                return subcls(realm, request, err)
            except error.PyAsn1Error:
                pass

        raise ParsingError("Invalid request.")

    def __init__(self, realm, request, err):
        self.realm = realm
        self.request = request

        if len(err) > 0:
            type = self.__class__.__name__[:0 - len(ProxyRequest.__name__)]
            raise ParsingError("%s request has %d extra bytes." %
                               (type, len(err)))

    def __str__(self):
        type = self.__class__.__name__[:0 - len(ProxyRequest.__name__)]
        return "%s %s-REQ (%d bytes)" % (self.realm, type,
                                         len(self.request) - 4)


class TGSProxyRequest(ProxyRequest):
    TYPE = asn1.TGSREQ


class ASProxyRequest(ProxyRequest):
    TYPE = asn1.ASREQ


class KPASSWDProxyRequest(ProxyRequest):
    TYPE = asn1.APREQ
    OFFSET = 10

    def __init__(self, realm, request, err):
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
        (apreq, err) = decoder.decode(request[10:length + 10],
                                      asn1Spec=asn1.APREQ())
        (krbpriv, err) = decoder.decode(request[length + 10:],
                                        asn1Spec=asn1.KRBPriv())

        super(KPASSWDProxyRequest, self).__init__(realm, request, err)
        self.version = version

    def __str__(self):
        tmp = super(KPASSWDProxyRequest, self).__str__()
        tmp += " (version 0x%04x)" % self.version
        return tmp


def decode(data):
    return ProxyRequest.parse(data)


def encode(data):
    rep = asn1.ProxyMessage()
    rep.setComponentByName('message', data)
    return encoder.encode(rep)
