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

import contextlib
import os
import socket
import struct
import tempfile
import unittest
from base64 import b64decode
try:
    from unittest import mock
except ImportError:  # pragma: no cover
    import mock


from dns.rdataclass import IN as RDCLASS_IN
from dns.rdatatype import SRV as RDTYPE_SRV
from dns.rdtypes.IN.SRV import SRV

try:
    from webtest import TestApp as WebTestApp
except ImportError:
    print("webtest not installed!  Tests will be skipped")
    WebTestApp = "skip"

import kdcproxy
from kdcproxy import codec
from kdcproxy import config
from kdcproxy.config import mit


HERE = os.path.dirname(os.path.abspath(__file__))
KRB5_CONFIG = os.path.join(HERE, 'tests.krb5.conf')


@unittest.skipIf(WebTestApp == "skip", "webtest not installed")
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
        self.tapp = WebTestApp(self.app)

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
    @mock.patch('socket.socket')
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
    @mock.patch('socket.socket')
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

    @mock.patch("socket.getaddrinfo", return_value=addrinfo)
    @mock.patch("socket.socket")
    def test_tcp_message_length_exceeds_max(self, m_socket, m_getaddrinfo):
        # Test that TCP messages with length > MAX_LENGTH raise ValueError
        # Create a message claiming to be larger than MAX_LENGTH
        max_len = self.app.MAX_LENGTH
        # Length prefix claiming message is larger than allowed
        oversized_length = max_len + 1
        malicious_msg = struct.pack("!I", oversized_length)

        # Mock socket to return the malicious length prefix
        mock_sock = m_socket.return_value
        mock_sock.recv.return_value = malicious_msg
        mock_sock.getsockopt.return_value = socket.SOCK_STREAM

        # Manually call the receive method to test it
        read_buffers = {}
        with self.assertRaises(ValueError) as cm:
            self.app._Application__handle_recv(mock_sock, read_buffers)

        self.assertIn("exceeds the maximum length", str(cm.exception))
        self.assertIn(str(max_len), str(cm.exception))

    @mock.patch("socket.getaddrinfo", return_value=addrinfo)
    @mock.patch("socket.socket")
    def test_tcp_message_data_exceeds_expected_length(
        self, m_socket, m_getaddrinfo
    ):
        # Test that receiving more data than expected raises ValueError
        # Create a message with length = 100 but send more data
        expected_length = 100
        length_prefix = struct.pack("!I", expected_length)
        # Send more data than the length prefix indicates
        extra_data = b"X" * (expected_length + 10)
        malicious_msg = length_prefix + extra_data

        mock_sock = m_socket.return_value
        mock_sock.recv.return_value = malicious_msg
        mock_sock.getsockopt.return_value = socket.SOCK_STREAM

        read_buffers = {}
        with self.assertRaises(ValueError) as cm:
            self.app._Application__handle_recv(mock_sock, read_buffers)

        self.assertIn("exceeds its expected length", str(cm.exception))

    @mock.patch("socket.getaddrinfo", return_value=addrinfo)
    @mock.patch("socket.socket")
    def test_tcp_eof_returns_buffered_data(self, m_socket, m_getaddrinfo):
        # Test that EOF returns any buffered data
        initial_data = b"\x00\x00\x00\x10"  # Length = 16
        mock_sock = m_socket.return_value
        mock_sock.getsockopt.return_value = socket.SOCK_STREAM

        # First recv returns some data, second returns empty (EOF)
        mock_sock.recv.side_effect = [initial_data, b""]

        read_buffers = {}
        # First call buffers the data
        result = self.app._Application__handle_recv(mock_sock, read_buffers)
        self.assertIsNone(result)  # Not complete yet

        # Second call gets EOF and returns buffered data
        result = self.app._Application__handle_recv(mock_sock, read_buffers)
        self.assertEqual(result, initial_data)
        # Buffer should be cleaned up
        self.assertNotIn(mock_sock, read_buffers)


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
        # manual decode
        request, realm, _ = codec.asn1mod.decode_proxymessage(data)
        self.assertEqual(realm, self.realm)
        inst = cls.parse_request(realm, request)
        self.assertIsInstance(inst, cls)
        self.assertEqual(inst.realm, self.realm)
        self.assertEqual(inst.request, request)
        if cls is codec.KPASSWDProxyRequest:
            self.assertEqual(inst.version, 1)
        # codec decode
        outer = codec.decode(data)
        self.assertEqual(outer.realm, self.realm)
        self.assertIsInstance(outer, cls)
        # re-decode
        der = codec.encode(outer.request)
        self.assertIsInstance(der, bytes)
        decoded = codec.decode(der)
        self.assertIsInstance(decoded, cls)
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

    @contextlib.contextmanager
    def temp_config_file(self, content):
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".conf"
        ) as f:
            f.write(content)
            config_file = f.name

        try:
            yield config_file
        finally:
            os.remove(config_file)

    def test_mit_config(self):
        with mock.patch.dict('os.environ', {'KRB5_CONFIG': KRB5_CONFIG}):
            cfg = mit.MITConfig()

        self.assertIs(cfg.param('KDCPROXY.TEST', 'use_dns'), None)
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

    def test_kdcproxy_config_realm_configured(self):
        with self.temp_config_file(
            """[REALM1.TEST]
               kerberos = kerberos://kdc1.realm1.test:88
               [REALM2.TEST]
               kpasswd = kpasswd://kpwd.realm2.test:464\n"""
        ) as config_file:
            cfg = config.KDCProxyConfig(filenames=[config_file])

            # Test configured realms
            self.assertTrue(cfg.realm_configured("REALM1.TEST"))
            self.assertTrue(cfg.realm_configured("REALM2.TEST"))

            # Test unconfigured realm
            self.assertFalse(cfg.realm_configured("UNKNOWN.TEST"))

            # Test that 'global' cannot be used as realm name
            with self.assertRaises(ValueError):
                cfg.realm_configured("global")

    def test_kdcproxy_config_param(self):
        with self.temp_config_file(
            """[global]
               silence_port_warn = true
               [REALM1.TEST]
               use_dns = false
               kerberos = kerberos://kdc1.realm1.test:88
               [REALM2.TEST]
               kerberos = kerberos://kdc2.realm2.test:88"""
        ) as config_file:
            cfg = config.KDCProxyConfig(filenames=[config_file])

            # Test realm-specific parameter overrides global
            self.assertFalse(cfg.param("REALM1.TEST", "use_dns"))

            # Test fallback to global parameter
            self.assertTrue(cfg.param("REALM1.TEST", "silence_port_warn"))
            self.assertTrue(cfg.param("REALM2.TEST", "use_dns"))
            self.assertTrue(cfg.param("REALM2.TEST", "silence_port_warn"))

            # Test invalid parameter
            with self.assertRaises(ValueError):
                cfg.param("REALM1.TEST", "invalid_param")

            # Test that 'global' cannot be used as realm name
            with self.assertRaises(ValueError):
                cfg.param("global", "use_dns")

    def test_kdcproxy_config_lookup(self):
        with self.temp_config_file(
            "[REALM.TEST]\n"
            "kerberos = kerberos://kdc1.test:88 "
            "kerberos://kdc2.test:88\n"
            "kpasswd = kpasswd://kpwd.test:464"
        ) as config_file:
            cfg = config.KDCProxyConfig(filenames=[config_file])

            # Test kerberos lookup
            self.assertEqual(
                cfg.lookup("REALM.TEST"),
                ("kerberos://kdc1.test:88", "kerberos://kdc2.test:88"),
            )

            # Test kpasswd lookup
            self.assertEqual(
                cfg.lookup("REALM.TEST", kpasswd=True),
                ("kpasswd://kpwd.test:464",),
            )

            # Test unconfigured realm
            self.assertEqual(cfg.lookup("UNKNOWN.TEST"), ())

            # Test that 'global' cannot be used as realm name
            with self.assertRaises(ValueError):
                cfg.lookup("global")

    @mock.patch("dns.resolver.query")
    def test_dns_blocked_for_undeclared_realms(self, m_query):
        with mock.patch.object(config.KDCProxyConfig, "default_filenames", []):
            resolver = config.MetaResolver()

            # DNS should NOT be used for unconfigured realm
            result = resolver.lookup("UNCONFIGURED.TEST")
            self.assertEqual(result, ())
            m_query.assert_not_called()

    @mock.patch("dns.resolver.query")
    def test_use_dns_false_disables_dns_discovery(self, m_query):
        # Test exact realm section
        with self.temp_config_file(
            """[global]
               use_dns = false
               [REALM.TEST]
               ; Exact realm declared but no servers specified"""
        ) as config_file:
            with mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()

                # DNS should NOT be used when use_dns is false for exact realm
                result = resolver.lookup("REALM.TEST")
                self.assertEqual(result, ())
                m_query.assert_not_called()

        # Test wildcard realm section
        m_query.reset_mock()
        with self.temp_config_file(
            """[global]
               use_dns = false
               [*EXAMPLE.COM]
               ; Wildcard realm declared but no servers specified"""
        ) as config_file:
            with mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()

                # DNS should NOT be used when use_dns is false for wildcard
                # realm
                result = resolver.lookup("SUB.EXAMPLE.COM")
                self.assertEqual(result, ())
                m_query.assert_not_called()

    @mock.patch("dns.resolver.query")
    def test_use_dns_true_enables_dns_for_declared_realms(self, m_query):
        # Test exact realm section
        with self.temp_config_file(
            """[global]
               use_dns = true
               [REALM.TEST]
               ; Exact realm declared but no servers specified"""
        ) as config_file:
            tcp_srv = [self.mksrv("0 0 88 kdc.realm.test.")]
            udp_srv = []
            m_query.side_effect = [tcp_srv, udp_srv]

            with mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()

                # DNS SHOULD be used when exact realm is declared and use_dns
                # is true
                result = resolver.lookup("REALM.TEST")
                self.assertEqual(result, ("kerberos://kdc.realm.test:88",))
                self.assertEqual(m_query.call_count, 2)

        # Test wildcard realm section
        m_query.reset_mock()
        with self.temp_config_file(
            """[global]
               use_dns = true
               [*EXAMPLE.COM]
               ; Wildcard realm declared but no servers specified"""
        ) as config_file:
            tcp_srv = [self.mksrv("0 0 88 kdc.sub.example.com.")]
            udp_srv = []
            m_query.side_effect = [tcp_srv, udp_srv]

            with mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()

                # DNS SHOULD be used when wildcard realm matches and use_dns
                # is true
                result = resolver.lookup("SUB.EXAMPLE.COM")
                self.assertEqual(
                    result, ("kerberos://kdc.sub.example.com:88",)
                )
                self.assertEqual(m_query.call_count, 2)

    @mock.patch("logging.Logger.warning")
    @mock.patch("dns.resolver.query")
    def test_dns_discovery_warns_on_nonstandard_port(
        self, m_query, m_log_warning
    ):
        # Test exact realm section
        with self.temp_config_file(
            """[REALM.TEST]"""
        ) as config_file:
            # DNS returns KDC on non-standard port
            tcp_srv = [self.mksrv("0 0 1088 kdc.realm.test.")]
            udp_srv = []
            m_query.side_effect = [tcp_srv, udp_srv]

            with mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()
                result = resolver.lookup("REALM.TEST")

                # Should return the server
                self.assertEqual(result, ("kerberos://kdc.realm.test:1088",))

                # Should log warning about non-standard port for exact realm
                m_log_warning.assert_called_once()
                args = m_log_warning.call_args[0]
                self.assertIn("non-standard port", args[0])
                self.assertEqual(args[5], 1088)  # port
                self.assertEqual(args[6], 88)  # expected port

        # Test wildcard realm section
        m_query.reset_mock()
        m_log_warning.reset_mock()
        with self.temp_config_file(
            """[*EXAMPLE.COM]"""
        ) as config_file:
            # DNS returns KDC on non-standard port
            tcp_srv = [self.mksrv("0 0 1088 kdc.sub.example.com.")]
            udp_srv = []
            m_query.side_effect = [tcp_srv, udp_srv]

            with mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()
                result = resolver.lookup("SUB.EXAMPLE.COM")

                # Should return the server
                self.assertEqual(
                    result, ("kerberos://kdc.sub.example.com:1088",)
                )

                # Should log warning about non-standard port for wildcard realm
                m_log_warning.assert_called_once()
                args = m_log_warning.call_args[0]
                self.assertIn("non-standard port", args[0])
                self.assertEqual(args[5], 1088)  # port
                self.assertEqual(args[6], 88)  # expected port

    @mock.patch("logging.Logger.warning")
    @mock.patch("dns.resolver.query")
    def test_silence_port_warn_suppresses_nonstandard_port_warnings(
        self, m_query, m_log_warning
    ):
        # Test exact realm section
        with self.temp_config_file(
            """[REALM.TEST]
               silence_port_warn = true"""
        ) as config_file:
            # DNS returns KDC on non-standard port
            tcp_srv = [self.mksrv("0 0 1088 kdc.realm.test.")]
            udp_srv = []
            m_query.side_effect = [tcp_srv, udp_srv]

            with mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()
                result = resolver.lookup("REALM.TEST")

                # Should return the server
                self.assertEqual(result, ("kerberos://kdc.realm.test:1088",))

                # Should NOT log warning when silenced for exact realm
                m_log_warning.assert_not_called()

        # Test wildcard realm section
        m_query.reset_mock()
        m_log_warning.reset_mock()
        with self.temp_config_file(
            """[*EXAMPLE.COM]
               silence_port_warn = true"""
        ) as config_file:
            # DNS returns KDC on non-standard port
            tcp_srv = [self.mksrv("0 0 1088 kdc.sub.example.com.")]
            udp_srv = []
            m_query.side_effect = [tcp_srv, udp_srv]

            with mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()
                result = resolver.lookup("SUB.EXAMPLE.COM")

                # Should return the server
                self.assertEqual(
                    result, ("kerberos://kdc.sub.example.com:1088",)
                )

                # Should NOT log warning when silenced for wildcard realm
                m_log_warning.assert_not_called()

    @mock.patch("dns.resolver.query")
    def test_configured_servers_preferred_over_dns_discovery(self, m_query):
        # Create a config with servers configured
        with self.temp_config_file(
            """[REALM.TEST]
               kerberos = kerberos://configured-kdc.test:88"""
        ) as config_file:
            with mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()
                result = resolver.lookup("REALM.TEST")

                # Should return configured server, not DNS
                self.assertEqual(
                    result, ("kerberos://configured-kdc.test:88",)
                )

                # DNS should not be queried when servers are configured
                m_query.assert_not_called()

    @mock.patch("dns.resolver.query")
    def test_mit_realm_prefers_configured_servers_over_dns(self, m_query):
        # Test that realm in MIT config uses configured servers even when
        # use_dns = true
        with self.temp_config_file(
            """[global]
               use_dns = true
               configs = mit"""
        ) as config_file:
            with mock.patch.dict(
                "os.environ", {"KRB5_CONFIG": KRB5_CONFIG}
            ), mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()
                result = resolver.lookup("KDCPROXY.TEST")

                # Should return MIT-configured servers (from tests.krb5.conf)
                self.assertEqual(
                    result,
                    (
                        "kerberos://k1.kdcproxy.test.:88",
                        "kerberos://k2.kdcproxy.test.:1088",
                    ),
                )

                # DNS should NOT be queried when servers are in MIT config
                m_query.assert_not_called()

    @mock.patch("dns.resolver.query")
    def test_mit_realm_uses_configured_servers_when_use_dns_false(
        self, m_query
    ):
        # Test that realm in MIT config uses configured servers when
        # use_dns = false
        with self.temp_config_file(
            """[global]
               use_dns = false
               configs = mit"""
        ) as config_file:
            with mock.patch.dict(
                "os.environ", {"KRB5_CONFIG": KRB5_CONFIG}
            ), mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()
                result = resolver.lookup("KDCPROXY.TEST")

                # Should return MIT-configured servers
                self.assertEqual(
                    result,
                    (
                        "kerberos://k1.kdcproxy.test.:88",
                        "kerberos://k2.kdcproxy.test.:1088",
                    ),
                )

                # DNS should NOT be queried
                m_query.assert_not_called()

    @mock.patch("dns.resolver.query")
    def test_mit_kpasswd_prefers_configured_servers_over_dns(self, m_query):
        # Test that kpasswd servers from MIT config are used even when
        # use_dns = true
        with self.temp_config_file(
            """[global]
               use_dns = true
               configs = mit"""
        ) as config_file:
            with mock.patch.dict(
                "os.environ", {"KRB5_CONFIG": KRB5_CONFIG}
            ), mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()
                result = resolver.lookup("KDCPROXY.TEST", kpasswd=True)

                # Should return MIT-configured kpasswd servers
                self.assertEqual(
                    result,
                    (
                        "kpasswd://adm.kdcproxy.test.:1749",
                        "kpasswd://adm.kdcproxy.test.",
                    ),
                )

                # DNS should NOT be queried
                m_query.assert_not_called()

    @mock.patch("dns.resolver.query")
    def test_kdcproxy_declared_realm_uses_dns_when_no_servers(self, m_query):
        # Test that a realm in kdcproxy.conf (but not MIT) will use DNS when no
        # servers are configured
        with self.temp_config_file(
            """[global]
               configs = mit
               [REALM.TEST]
               ; Realm section exists but no servers configured"""
        ) as config_file:
            tcp_srv = [self.mksrv("0 0 88 kdc.realm.test.")]
            udp_srv = []
            m_query.side_effect = [tcp_srv, udp_srv]

            with mock.patch.dict(
                "os.environ", {"KRB5_CONFIG": KRB5_CONFIG}
            ), mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()
                result = resolver.lookup("REALM.TEST")

                # Should use DNS since realm is in config but has no servers
                self.assertEqual(result, ("kerberos://kdc.realm.test:88",))
                self.assertEqual(m_query.call_count, 2)

    @mock.patch("dns.resolver.query")
    def test_realm_specific_use_dns_overrides_global(self, m_query):
        # Test that realm-specific use_dns overrides global setting for a realm
        # that's in MIT config
        with self.temp_config_file(
            """[global]
               use_dns = true
               configs = mit
               [KDCPROXY.TEST]
               use_dns = false"""
        ) as config_file:
            with mock.patch.dict(
                "os.environ", {"KRB5_CONFIG": KRB5_CONFIG}
            ), mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()

                # First check: should return MIT servers
                result = resolver.lookup("KDCPROXY.TEST")
                self.assertEqual(
                    result,
                    (
                        "kerberos://k1.kdcproxy.test.:88",
                        "kerberos://k2.kdcproxy.test.:1088",
                    ),
                )

                # DNS should not be queried due to realm override
                m_query.assert_not_called()

    @mock.patch("dns.resolver.query")
    def test_kdcproxy_servers_override_mit_servers(self, m_query):
        # Test that servers configured in kdcproxy.conf take precedence over
        # MIT config servers
        with self.temp_config_file(
            """[global]
               configs = mit
               [KDCPROXY.TEST]
               kerberos = kerberos://override.test:88"""
        ) as config_file:
            with mock.patch.dict(
                "os.environ", {"KRB5_CONFIG": KRB5_CONFIG}
            ), mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()
                result = resolver.lookup("KDCPROXY.TEST")

                # Should return kdcproxy.conf servers, not MIT servers
                self.assertEqual(result, ("kerberos://override.test:88",))

                # DNS should not be queried
                m_query.assert_not_called()

    @mock.patch("dns.resolver.query")
    def test_undeclared_realm_blocks_dns_despite_use_dns_true(self, m_query):
        # Test that a realm NOT in MIT and NOT in kdcproxy.conf will NOT use
        # DNS even with use_dns = true (security restriction)
        with self.temp_config_file(
            """[global]
               use_dns = true
               configs = mit"""
        ) as config_file:
            with mock.patch.dict(
                "os.environ", {"KRB5_CONFIG": KRB5_CONFIG}
            ), mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()
                result = resolver.lookup("UNCONFIGURED.REALM")

                # Should return empty - no DNS lookup
                self.assertEqual(result, ())

                # DNS should NOT be queried for unconfigured realm
                m_query.assert_not_called()

    @mock.patch("dns.resolver.query")
    def test_mit_declared_realm_without_servers_uses_dns(self, m_query):
        # Test that a realm in MIT config but WITHOUT KDC servers configured
        # will use DNS

        # Create a krb5.conf with a realm section but no kdc entries
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".conf"
        ) as krb5_file:
            krb5_file.write(
                """[libdefaults]
                   default_realm = EMPTY.REALM

                   [realms]
                   EMPTY.REALM = {
                       default_domain = empty.realm
                   }"""
            )
            krb5_conf = krb5_file.name

        # Create kdcproxy.conf
        with self.temp_config_file(
            """[global]
               configs = mit"""
        ) as config_file:
            tcp_srv = [self.mksrv("0 0 88 kdc.empty.realm.")]
            udp_srv = []
            m_query.side_effect = [tcp_srv, udp_srv]

            with mock.patch.dict(
                "os.environ", {"KRB5_CONFIG": krb5_conf}
            ), mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()
                result = resolver.lookup("EMPTY.REALM")

                # Should use DNS because:
                # 1. Realm is in MIT config (realm_configured returns True)
                # 2. No servers configured in MIT config
                # 3. use_dns enabled globally by default
                self.assertEqual(result, ("kerberos://kdc.empty.realm:88",))

                # DNS SHOULD be queried
                self.assertEqual(m_query.call_count, 2)
                m_query.assert_any_call(
                    "_kerberos._tcp.EMPTY.REALM", RDTYPE_SRV
                )
                m_query.assert_any_call(
                    "_kerberos._udp.EMPTY.REALM", RDTYPE_SRV
                )
            os.remove(krb5_conf)

    def test_kdcproxy_config_realm_wildcard_matching(self):
        # Test realm matching with wildcard patterns
        with self.temp_config_file(
            """[global]
               use_dns = false
               [SPECIFIC.SUB.EXAMPLE.COM]
               kerberos = kerberos://specific.example.com:88
               [*SUB.EXAMPLE.COM]
               use_dns = true
               [*EXAMPLE.COM]
               silence_port_warn = true"""
        ) as config_file:
            cfg = config.KDCProxyConfig(filenames=[config_file])

            # Test exact match
            self.assertTrue(cfg.realm_configured("SPECIFIC.SUB.EXAMPLE.COM"))
            self.assertEqual(
                cfg.lookup("SPECIFIC.SUB.EXAMPLE.COM"),
                ("kerberos://specific.example.com:88",),
            )

            # Test wildcard matching for *SUB.EXAMPLE.COM
            self.assertTrue(cfg.realm_configured("OTHER.SUB.EXAMPLE.COM"))
            # Wildcard sections don't support kerberos/kpasswd params
            self.assertEqual(cfg.lookup("OTHER.SUB.EXAMPLE.COM"), ())

            # Test wildcard matching for *EXAMPLE.COM
            self.assertTrue(cfg.realm_configured("FOO.EXAMPLE.COM"))
            self.assertEqual(cfg.lookup("FOO.EXAMPLE.COM"), ())

            # Test wildcard matches exact realm name (EXAMPLE.COM matches
            # *EXAMPLE.COM)
            self.assertTrue(cfg.realm_configured("EXAMPLE.COM"))
            self.assertTrue(cfg.param("EXAMPLE.COM", "silence_port_warn"))

            # Test multi-level subdomain matches wildcard
            self.assertTrue(cfg.realm_configured("A.B.C.EXAMPLE.COM"))

            # Test non-matching realm (MYEXAMPLE.COM should NOT match
            # *EXAMPLE.COM)
            self.assertFalse(cfg.realm_configured("MYEXAMPLE.COM"))
            self.assertEqual(cfg.lookup("MYEXAMPLE.COM"), ())

            # Test other non-matching realm
            self.assertFalse(cfg.realm_configured("OTHER.DOMAIN"))
            self.assertEqual(cfg.lookup("OTHER.DOMAIN"), ())

    def test_kdcproxy_config_param_wildcard_matching(self):
        # Test parameter lookup with wildcard patterns
        with self.temp_config_file(
            """[global]
               use_dns = false
               silence_port_warn = false
               [*EXAMPLE.COM]
               use_dns = true
               silence_port_warn = true
               [SPECIFIC.EXAMPLE.COM]
               silence_port_warn = false"""
        ) as config_file:
            cfg = config.KDCProxyConfig(filenames=[config_file])

            # Test exact match takes precedence for parameters
            self.assertTrue(cfg.param("SPECIFIC.EXAMPLE.COM", "use_dns"))
            self.assertFalse(
                cfg.param("SPECIFIC.EXAMPLE.COM", "silence_port_warn")
            )

            # Test wildcard parameter matching
            self.assertTrue(cfg.param("OTHER.EXAMPLE.COM", "use_dns"))
            self.assertTrue(
                cfg.param("OTHER.EXAMPLE.COM", "silence_port_warn")
            )

            # Test fallback to global when no wildcard match
            self.assertFalse(cfg.param("OTHER.DOMAIN", "use_dns"))
            self.assertFalse(cfg.param("OTHER.DOMAIN", "silence_port_warn"))

    def test_wildcard_specificity_determines_priority(self):
        # Test that more specific wildcards take precedence
        with self.temp_config_file(
            """[global]
               use_dns = false
               [*EXAMPLE.COM]
               silence_port_warn = true
               [*SUB.EXAMPLE.COM]
               use_dns = true"""
        ) as config_file:
            cfg = config.KDCProxyConfig(filenames=[config_file])

            # More specific wildcard (*SUB.EXAMPLE.COM) should match first
            self.assertTrue(cfg.param("FOO.SUB.EXAMPLE.COM", "use_dns"))
            # Should also get parameter from broader wildcard
            self.assertTrue(
                cfg.param("FOO.SUB.EXAMPLE.COM", "silence_port_warn")
            )

            # Broader wildcard should match other subdomains
            self.assertTrue(
                cfg.param("FOO.OTHER.EXAMPLE.COM", "silence_port_warn")
            )
            # Should fallback to global for use_dns
            self.assertFalse(cfg.param("FOO.OTHER.EXAMPLE.COM", "use_dns"))

    @mock.patch("dns.resolver.query")
    def test_kdcproxy_config_exact_realm_priority_over_wildcard(self, m_query):
        # Test that exact realm sections take precedence over wildcard sections
        with self.temp_config_file(
            """[global]
               use_dns = false
               silence_port_warn = false
               [*EXAMPLE.COM]
               use_dns = true
               silence_port_warn = true
               [SPECIFIC.EXAMPLE.COM]
               kerberos = kerberos://specific-kdc.example.com:88
               use_dns = false"""
        ) as config_file:
            with mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()

                # Exact realm section should take priority
                self.assertTrue(
                    resolver._MetaResolver__config.realm_configured(
                        "SPECIFIC.EXAMPLE.COM"
                    )
                )

                # Should get kerberos from exact realm section
                result = resolver.lookup("SPECIFIC.EXAMPLE.COM")
                self.assertEqual(
                    result,
                    ("kerberos://specific-kdc.example.com:88",),
                )

                # DNS should NOT be called because:
                # 1. Exact realm has configured servers
                # 2. Exact realm has use_dns=false (takes priority over
                #    wildcard)
                m_query.assert_not_called()

                # Verify exact realm's use_dns=false takes priority
                self.assertFalse(
                    resolver._MetaResolver__config.param(
                        "SPECIFIC.EXAMPLE.COM", "use_dns"
                    )
                )

                # Should get silence_port_warn from wildcard since not in exact
                # section
                self.assertTrue(
                    resolver._MetaResolver__config.param(
                        "SPECIFIC.EXAMPLE.COM", "silence_port_warn"
                    )
                )

    def test_dns_realm_discovery_param_defaults_false(self):
        # Test the dns_realm_discovery global parameter
        with self.temp_config_file(
            """[global]
               dns_realm_discovery = true"""
        ) as config_file:
            cfg = config.KDCProxyConfig(filenames=[config_file])

            # Test that dns_realm_discovery can be read
            self.assertTrue(cfg.param(None, "dns_realm_discovery"))

            # Test default value when not specified
            cfg2 = config.KDCProxyConfig(filenames=[])
            self.assertFalse(cfg2.param(None, "dns_realm_discovery"))

    @mock.patch("dns.resolver.query")
    def test_dns_realm_discovery_true_allows_undeclared_realms(self, m_query):
        # Test that dns_realm_discovery allows DNS for unconfigured realms
        with self.temp_config_file(
            """[global]
               dns_realm_discovery = true"""
        ) as config_file:
            tcp_srv = [self.mksrv("0 0 88 kdc.unconfigured.test.")]
            udp_srv = []
            m_query.side_effect = [tcp_srv, udp_srv]

            with mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()

                # DNS SHOULD be used for unconfigured realm when
                # dns_realm_discovery = true
                result = resolver.lookup("UNCONFIGURED.TEST")
                self.assertEqual(
                    result, ("kerberos://kdc.unconfigured.test:88",)
                )
                self.assertEqual(m_query.call_count, 2)

    @mock.patch("dns.resolver.query")
    def test_dns_realm_discovery_false_blocks_undeclared_realms(self, m_query):
        # Test that dns_realm_discovery=false restricts DNS to configured
        # realms
        with self.temp_config_file(
            """[global]
               dns_realm_discovery = false"""
        ) as config_file:
            with mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()

                # DNS should NOT be used for unconfigured realm when
                # dns_realm_discovery = false
                result = resolver.lookup("UNCONFIGURED.TEST")
                self.assertEqual(result, ())
                m_query.assert_not_called()

    @mock.patch("dns.resolver.query")
    def test_wildcard_realm_uses_dns_despite_dns_realm_discovery_false(
        self, m_query
    ):
        # Test that wildcard-matched realms can use DNS discovery
        with self.temp_config_file(
            """[global]
               dns_realm_discovery = false
               [*EXAMPLE.COM]"""
        ) as config_file:
            tcp_srv = [self.mksrv("0 0 88 kdc.sub.example.com.")]
            udp_srv = []
            m_query.side_effect = [tcp_srv, udp_srv]

            with mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()

                # DNS SHOULD be used for wildcard-matched realm even when
                # dns_realm_discovery = false
                result = resolver.lookup("SUB.EXAMPLE.COM")
                self.assertEqual(
                    result, ("kerberos://kdc.sub.example.com:88",)
                )
                self.assertEqual(m_query.call_count, 2)

    @mock.patch("dns.resolver.query")
    def test_use_dns_defaults_to_true(self, m_query):
        # Test that use_dns defaults to true when not set
        with self.temp_config_file(
            """[REALM.TEST]
               ; Realm declared but use_dns not specified"""
        ) as config_file:
            tcp_srv = [self.mksrv("0 0 88 kdc.realm.test.")]
            udp_srv = []
            m_query.side_effect = [tcp_srv, udp_srv]

            with mock.patch.object(
                config.KDCProxyConfig, "default_filenames", [config_file]
            ):
                resolver = config.MetaResolver()

                # DNS SHOULD be used when use_dns is not set (defaults to true)
                result = resolver.lookup("REALM.TEST")
                self.assertEqual(result, ("kerberos://kdc.realm.test:88",))
                self.assertEqual(m_query.call_count, 2)

    @mock.patch("dns.resolver.query")
    def test_dns_realm_discovery_defaults_to_false(self, m_query):
        # Test that dns_realm_discovery defaults to false for security
        with mock.patch.object(config.KDCProxyConfig, "default_filenames", []):
            resolver = config.MetaResolver()

            # DNS should NOT be used for unconfigured realm by default
            result = resolver.lookup("UNCONFIGURED.TEST")
            self.assertEqual(result, ())
            m_query.assert_not_called()


if __name__ == "__main__":
    unittest.main()
