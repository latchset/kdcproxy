# Copyright (C) 2015, Red Hat, Inc.
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
import unittest
from base64 import b64decode
try:
    from unittest import mock
except ImportError:  # pragma: no cover
    import mock


from dns.rdataclass import IN as RDCLASS_IN
from dns.rdatatype import SRV as RDTYPE_SRV
from dns.rdtypes.IN.SRV import SRV

from pyasn1.codec.der import decoder, encoder

from webtest import TestApp

import kdcproxy
# from kdcproxy import asn1
from kdcproxy import codec
from kdcproxy import config
from kdcproxy.config import mit

HERE = os.path.dirname(os.path.abspath(__file__))
KRB5_CONFIG = os.path.join(HERE, 'tests.krb5.conf')


class KDCProxyWSGITests(unittest.TestCase):
    addrinfo = [
        (2, 1, 6, '', ('128.66.0.2', 88)),
        (2, 2, 17, '', ('128.66.0.2', 88)),
        (2, 3, 0, '', ('128.66.0.2', 88))
    ]

    def setUp(self):  # noqa
        self.app = kdcproxy.Application()
        self.await_reply = self.app._Application__await_reply = mock.Mock()
        self.await_reply.return_value = b'RESPONSE'
        self.resolver = self.app._Application__resolver = mock.Mock()
        self.resolver.lookup.return_value = ["kerberos://k1.kdcproxy.test.:88"]
        self.tapp = TestApp(self.app)

    def post(self, body, expect_errors=False):
        return self.tapp.post(
            '/', body, [("Content-Type", "application/kerberos")],
            expect_errors=expect_errors
        )

    def assert_response(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'application/kerberos')
        self.assertEqual(response.body, b'0\x0c\xa0\n\x04\x08RESPONSE')

    def test_get(self):
        r = self.tapp.get('/', expect_errors=True)
        self.assertEqual(r.status_code, 405)
        self.assertEqual(r.status, '405 Method Not Allowed')
        self.assertEqual(r.text, 'Method not allowed (GET).')

    @mock.patch('socket.getaddrinfo', return_value=addrinfo)
    @mock.patch('socket.socket', autospec=True)
    def test_post_asreq(self, m_socket, m_getaddrinfo):
        response = self.post(KDCProxyCodecTests.asreq1)
        self.assert_response(response)
        self.resolver.lookup.assert_called_once_with('FREEIPA.LOCAL',
                                                     kpasswd=False)
        m_getaddrinfo.assert_called_once_with('k1.kdcproxy.test.', 88)
        m_socket.assert_called_once_with(2, 1, 6)
        m_socket.return_value.connect.assert_called_once_with(
            ('128.66.0.2', 88)
        )

    @mock.patch('socket.getaddrinfo', return_value=addrinfo)
    @mock.patch('socket.socket', autospec=True)
    def test_post_kpasswd(self, m_socket, m_getaddrinfo):
        response = self.post(KDCProxyCodecTests.kpasswdreq)
        self.assert_response(response)
        self.resolver.lookup.assert_called_once_with('FREEIPA.LOCAL',
                                                     kpasswd=True)
        m_getaddrinfo.assert_called_once_with('k1.kdcproxy.test.', 88)
        m_socket.assert_called_once_with(2, 1, 6)
        m_socket.return_value.connect.assert_called_once_with(
            ('128.66.0.2', 88)
        )

    def test_no_server(self):
        self.resolver.lookup.reset_mock()
        self.resolver.lookup.return_value = []
        response = self.post(KDCProxyCodecTests.asreq1, True)
        self.resolver.lookup.assert_called_once_with('FREEIPA.LOCAL',
                                                     kpasswd=False)
        self.assertEqual(response.status_code, 503)

        self.resolver.lookup.reset_mock()
        self.resolver.lookup.return_value = []
        response = self.post(KDCProxyCodecTests.kpasswdreq, True)
        self.resolver.lookup.assert_called_once_with('FREEIPA.LOCAL',
                                                     kpasswd=True)
        self.assertEqual(response.status_code, 503)


def decode(data):
    data = data.replace(b'\\n', b'')
    data = data.replace(b' ', b'')
    return b64decode(data)


class KDCProxyCodecTests(unittest.TestCase):
    realm = 'FREEIPA.LOCAL'

    asreq1 = decode(b"""
        MIHEoIGwBIGtAAAAqWqBpjCBo6EDAgEFogMCAQqjDjAMMAqhBAICAJWiAgQApIGGMIGDo
        AcDBQBAAAAQoRIwEKADAgEBoQkwBxsFYWRtaW6iDxsNRlJFRUlQQS5MT0NBTKMiMCCgAw
        IBAqEZMBcbBmtyYnRndBsNRlJFRUlQQS5MT0NBTKURGA8yMDE1MDUxNDEwNDIzOFqnBgI
        EEchjtagUMBICARICARECARACARcCARkCARqhDxsNRlJFRUlQQS5MT0NBTA==
    """)

    asreq2 = decode(b"""
        MIIBJaCCARAEggEMAAABCGqCAQQwggEAoQMCAQWiAwIBCqNrMGkwDaEEAgIAhaIFBANNS
        VQwTKEDAgECokUEQzBBoAMCARKiOgQ48A25MkXWM1ZrTvaYMJcbFX7Hp7JW11omIwqOQd
        SSGKVZ9mzYLuL19RRhX9xrXbQS0klXRVgRWHMwCqEEAgIAlaICBACkgYYwgYOgBwMFAEA
        AABChEjAQoAMCAQGhCTAHGwVhZG1pbqIPGw1GUkVFSVBBLkxPQ0FMoyIwIKADAgECoRkw
        FxsGa3JidGd0Gw1GUkVFSVBBLkxPQ0FMpREYDzIwMTUwNTE0MTA0MjM4WqcGAgRXSy38q
        BQwEgIBEgIBEQIBEAIBFwIBGQIBGqEPGw1GUkVFSVBBLkxPQ0FM
    """)

    tgsreq = decode(b"""
        MIIDxaCCA7AEggOsAAADqGyCA6QwggOgoQMCAQWiAwIBDKOCAxowggMWMIICL6EDAgEBo
        oICJgSCAiJuggIeMIICGqADAgEFoQMCAQ6iBwMFAAAAAACjggFGYYIBQjCCAT6gAwIBBa
        EPGw1GUkVFSVBBLkxPQ0FMoiIwIKADAgECoRkwFxsGa3JidGd0Gw1GUkVFSVBBLkxPQ0F
        Mo4IBADCB/aADAgESoQMCAQGigfAEge3ODJahLoTF0Xl+DeWdBqy79TSJv6+L23WEuBQi
        CnvmiLGxFhe/zuW6LN9O0Ekb3moX4qFKW7bF/gw0GuuMemkIjLaZ2M5mZiaQQ456fU5dA
        +ntLs8C407x3TVu68TM1aDvQgyKVpQgTdjxTZVmdinueIxOQ5z2nTIyjA9W94umGrPIcc
        sOfwvTEqyVpXrQcXr2tj/o/WcDLh/hHMhlHRBr9uLBLdVh2xR1yRbwe/n1UsXckxRi/A/
        +YgGSW7YDFBXij9RpGaE0bpa8e4u/EkcQEgu66nwVrfNs/TvsTJ1VnL5LpicDZvXzm0gO
        y3OkgbowgbegAwIBEqKBrwSBrIWE4ylyvY7JpiGCJQJKpv8sd3tFK054UTDvs1UuBAiWz
        IwNOddrdb4YKKGC/ce3e/sX+CBvISNPsOqX4skXK0gnMCJaCU6H1QKNeJu1TJm8GxPQ28
        1B8ZrCnv9Vzput0YIXAFK1eoAfe9qnJVktLL9uwYfV7D4GDU634KtEvPeDTBVMmTVXpUR
        5HIXiE4Qw6bON74Ssg4n8YDoO0ZXdOIOOUh1+soMoUzjg2XIwgeChBAICAIiigdcEgdSg
        gdEwgc6hFzAVoAMCARChDgQMmmZqel1e6bYuSZBxooGyMIGvoAMCARKigacEgaQwxX40v
        E6S6aNej2Siwkr/JA/70sbSoR8JrET9q6DW0rtawnOzKGYYSNEs8GLWgeSQaqIKuWXDuT
        R898vv3RYY4nn1wSNQFFSOHxaVqdRzY55Z7HbO7OPTyQhPI31f1m8Tuxl7kpMM74Yhypj
        iQCe8RHrJUyCQay8AonQY11pRvRlwzcnbrB5GhegVmtp1Qhtv0Lj//yLHZ4MdVh5FV2N2
        8odz7KR2MHSgBwMFAEABAACiDxsNRlJFRUlQQS5MT0NBTKMnMCWgAwIBAaEeMBwbBGh0d
        HAbFGlwYXNydi5mcmVlaXBhLmxvY2FspREYDzIwMTUwNTE0MTA0MjM4WqcGAgRVUzCzqB
        QwEgIBEgIBEQIBEAIBFwIBGQIBGqEPGw1GUkVFSVBBLkxPQ0FM
    """)

    kpasswdreq = decode(b"""
        MIICeKCCAmMEggJfAAACWwJbAAECAm6CAf4wggH6oAMCAQWhAwIBDqIHAwUAAAAAAKOCA
        UFhggE9MIIBOaADAgEFoQ8bDUZSRUVJUEEuTE9DQUyiHTAboAMCAQGhFDASGwZrYWRtaW
        4bCGNoYW5nZXB3o4IBADCB/aADAgESoQMCAQGigfAEge3swqU5Z7QS15Hf8+o9UPdl3H7
        Xx+ZpEsg2Fj9b0KB/xnnkbTbJs4oic8h30jOtVfq589lWN/jx3CIRdyPndTfJLZCQZN4Q
        sm6Gye/czzfMFtIOdYSdDL0EpW5/adRsbX253dxqy7431s9Jxsx4xXIowOkD/cCHcrAw3
        SLchLXVXGbgcnnphAo+po8cJ7omMF0c0F0eOplKQkbbjoNJSO/TeIQJdgmUrxpy9c8Uhc
        ScdkajtyxGD9YvXDc8Ik7OCFn03e9bd791qasiBSTgCjWjV3IvcDohjF/RpxftA5LxmGS
        /C1KSG1AZBqivSMOkgZ8wgZygAwIBEqKBlASBkerR33SV6Gv+yTLbqByadkgmCAu4w1ms
        NifEss5TAhcEJEnpyqPbZgMfvksc+ULsnsdzovskhd1NbhJx+f9B0mxUzpNw1uRXMVbNw
        FGUSlYwVr+h1Hzs7/PLSsRV/jPNA+kbqbTcIkPOWe8OGGWuvbp24w6yrY3rcUCbEfhs+m
        xuSIJwMDwEUb2GqRwTkBhCGgd1UTBPoAMCAQWhAwIBFaNDMEGgAwIBEqI6BDh433pZMyL
        WiOUtyZnqOyiMoCe7ulv7TVyE5PGccaA3vXPzzBwh5P9wEFDl0alUBuHOKgBbtzOAgKEP
        Gw1GUkVFSVBBLkxPQ0FM
    """)

    def assert_decode(self, data, cls):
        outer = codec.decode(data)
        self.assertEqual(outer.realm, self.realm)
        self.assertIsInstance(outer, cls)
        if cls is not codec.KPASSWDProxyRequest:
            inner, err = decoder.decode(outer.request[outer.OFFSET:],
                                        asn1Spec=outer.TYPE())
            if err:  # pragma: no cover
                self.fail(err)
            self.assertIsInstance(inner, outer.TYPE)
            der = encoder.encode(inner)
            encoded = codec.encode(der)
            self.assertIsInstance(encoded, bytes)
        return outer

    def test_asreq(self):
        outer = self.assert_decode(self.asreq1, codec.ASProxyRequest)
        self.assertEqual(str(outer), 'FREEIPA.LOCAL AS-REQ (169 bytes)')
        outer = self.assert_decode(self.asreq2, codec.ASProxyRequest)
        self.assertEqual(str(outer), 'FREEIPA.LOCAL AS-REQ (264 bytes)')

    def test_tgsreq(self):
        outer = self.assert_decode(self.tgsreq, codec.TGSProxyRequest)
        self.assertEqual(str(outer), 'FREEIPA.LOCAL TGS-REQ (936 bytes)')

    def test_kpasswdreq(self):
        outer = self.assert_decode(self.kpasswdreq,
                                   codec.KPASSWDProxyRequest)
        self.assertEqual(
            str(outer),
            'FREEIPA.LOCAL KPASSWD-REQ (603 bytes) (version 0x0001)'
        )


class KDCProxyConfigTests(unittest.TestCase):

    def test_mit_config(self):
        with mock.patch.dict('os.environ', {'KRB5_CONFIG': KRB5_CONFIG}):
            cfg = mit.MITConfig()

        self.assertIs(cfg.use_dns(), False)
        self.assertEqual(
            cfg.lookup('KDCPROXY.TEST'),
            (
                'kerberos://k1.kdcproxy.test.:88',
                'kerberos://k2.kdcproxy.test.:1088'
            )
        )
        # wrong? man page says port 464 on admin server
        self.assertEqual(
            cfg.lookup('KDCPROXY.TEST', kpasswd=True),
            (
                'kpasswd://adm.kdcproxy.test.:1749',
                'kpasswd://adm.kdcproxy.test.'
            )
        )
        self.assertEqual(
            cfg.lookup('KDCPROXY.TEST', kpasswd=True),
            cfg.lookup('KDCPROXY.TEST', True)
        )
        self.assertEqual(cfg.lookup('KDCPROXY.MISSING'), ())
        self.assertEqual(cfg.lookup('KDCPROXY.MISSING', True), ())

    def mksrv(self, txt):
        priority, weight, port, target = txt.split(' ')
        return SRV(
            rdclass=RDCLASS_IN,  # Internet
            rdtype=RDTYPE_SRV,  # Server Selector
            priority=int(priority),
            weight=int(weight),
            port=int(port),
            target=target
        )

    @mock.patch('dns.resolver.query')
    def test_dns_config(self, m_query):
        cfg = config.DNSResolver()
        tcp = [
            self.mksrv('30 100 88 k1_tcp.kdcproxy.test.'),
            self.mksrv('10 100 1088 k2_tcp.kdcproxy.test.'),
        ]
        udp = [
            self.mksrv('0 100 88 k1_udp.kdcproxy.test.'),
            self.mksrv('10 100 1088 k2_udp.kdcproxy.test.'),
            self.mksrv('0 100 88 k3_udp.kdcproxy.test.'),
        ]
        m_query.side_effect = [tcp, udp]

        self.assertEqual(
            tuple(cfg.lookup('KDCPROXY.TEST')),
            (
                'kerberos://k2_tcp.kdcproxy.test:1088',
                'kerberos://k1_tcp.kdcproxy.test:88',
                'kerberos://k1_udp.kdcproxy.test:88',
                'kerberos://k3_udp.kdcproxy.test:88',
                'kerberos://k2_udp.kdcproxy.test:1088'
            )
        )
        self.assertEqual(m_query.call_count, 2)
        m_query.assert_any_call('_kerberos._tcp.KDCPROXY.TEST', RDTYPE_SRV)
        m_query.assert_any_call('_kerberos._udp.KDCPROXY.TEST', RDTYPE_SRV)

        m_query.reset_mock()
        adm = [
            self.mksrv('0 0 749 adm.kdcproxy.test.'),
        ]
        empty = []
        m_query.side_effect = (empty, adm, empty, empty)
        self.assertEqual(
            tuple(cfg.lookup('KDCPROXY.TEST', kpasswd=True)),
            (
                'kpasswd://adm.kdcproxy.test:749',
            )
        )
        self.assertEqual(m_query.call_count, 4)
        m_query.assert_any_call('_kpasswd._tcp.KDCPROXY.TEST', RDTYPE_SRV)
        m_query.assert_any_call('_kerberos-adm._tcp.KDCPROXY.TEST', RDTYPE_SRV)
        m_query.assert_any_call('_kpasswd._udp.KDCPROXY.TEST', RDTYPE_SRV)
        m_query.assert_any_call('_kerberos-adm._udp.KDCPROXY.TEST', RDTYPE_SRV)


if __name__ == "__main__":
    unittest.main()
