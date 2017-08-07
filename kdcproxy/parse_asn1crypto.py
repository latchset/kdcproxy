# Copyright (C) 2017, Red Hat, Inc.
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

from asn1crypto import core

from kdcproxy.exceptions import ASN1ParsingError


APPLICATION = 1


class KerberosString(core.GeneralString):
    """KerberosString ::= GeneralString (IA5String)

    For compatibility, implementations MAY choose to accept GeneralString
    values that contain characters other than those permitted by
    IA5String...
    """


class Realm(KerberosString):
    """Realm ::= KerberosString
    """


class ProxyMessage(core.Sequence):
    pretty_name = 'KDC-PROXY-MESSAGE'

    _fields = [
        ('kerb-message', core.OctetString, {
            'explicit': 0}),
        ('target-domain', Realm, {
            'explicit': 1, 'optional': True}),
        ('dclocator-hint', core.Integer, {
            'explicit': 2, 'optional': True}),
    ]


class ASREQ(core.Sequence):
    pretty_name = 'AS-REQ'

    explicit = (APPLICATION, 10)


class TGSREQ(core.Sequence):
    pretty_name = 'TGS-REQ'

    explicit = (APPLICATION, 12)


class APREQ(core.Sequence):
    pretty_name = 'AP-REQ'

    explicit = (APPLICATION, 14)


class KRBPriv(core.Sequence):
    pretty_name = 'KRBPRiv'

    explicit = (APPLICATION, 21)


def decode_proxymessage(data):
    req = ProxyMessage.load(data, strict=True)
    message = req['kerb-message'].native
    realm = req['target-domain'].native
    try:  # Python 3.x
        realm = str(realm, "utf-8")
    except TypeError:  # Python 2.x
        realm = str(realm)
    flags = req['dclocator-hint'].native
    return message, realm, flags


def encode_proxymessage(data):
    rep = ProxyMessage()
    rep['kerb-message'] = data
    return rep.dump()


def try_decode(data, cls):
    try:
        req = cls.load(data, strict=True)
    except ValueError as e:
        raise ASN1ParsingError(e)
    return req.pretty_name
