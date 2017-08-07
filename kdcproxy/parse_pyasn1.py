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

from pyasn1 import error
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import char, namedtype, tag, univ

from kdcproxy.exceptions import ASN1ParsingError, ParsingError


class ProxyMessageKerberosMessage(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
    )


class ProxyMessageTargetDomain(char.GeneralString):
    tagSet = char.GeneralString.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
    )


class ProxyMessageDCLocateHint(univ.Integer):
    tagSet = univ.Integer.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
    )


class ProxyMessage(univ.Sequence):
    pretty_name = 'KDC-PROXY-MESSAGE'

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('message', ProxyMessageKerberosMessage()),
        namedtype.OptionalNamedType('realm', ProxyMessageTargetDomain()),
        namedtype.OptionalNamedType('flags', ProxyMessageDCLocateHint())
    )


class ASREQ(univ.Sequence):
    pretty_name = 'AS-REQ'

    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 10)
    )


class TGSREQ(univ.Sequence):
    pretty_name = 'TGS-REQ'

    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 12)
    )


class APREQ(univ.Sequence):
    pretty_name = 'AP-REQ'

    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 14)
    )


class KRBPriv(univ.Sequence):
    pretty_name = 'KRBPRiv'

    tagSet = univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 21)
    )


def decode_proxymessage(data):
    try:
        req, tail = decoder.decode(data, asn1Spec=ProxyMessage())
    except error.PyAsn1Error as e:
        raise ASN1ParsingError(e)
    if tail:
        raise ParsingError("Invalid request.")
    message = req.getComponentByName('message').asOctets()
    realm = req.getComponentByName('realm')
    if realm.hasValue():
        try:  # Python 3.x
            realm = str(realm, "utf-8")
        except TypeError:  # Python 2.x
            realm = str(realm)
    else:
        realm = None
    flags = req.getComponentByName('flags')
    flags = int(flags) if flags.hasValue() else None
    return message, realm, flags


def encode_proxymessage(data):
    rep = ProxyMessage()
    rep.setComponentByName('message', data)
    return encoder.encode(rep)


def try_decode(data, cls):
    try:
        req, tail = decoder.decode(data, asn1Spec=cls())
    except error.PyAsn1Error as e:
        raise ASN1ParsingError(e)
    if tail:
        raise ParsingError("%s request has %d extra bytes." %
                           (cls.pretty_name, len(tail)))
    return cls.pretty_name
