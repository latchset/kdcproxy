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

import unittest

from webtest import TestApp

import kdcproxy
# from kdcproxy import asn1
# from kdcproxy import codec
# from kdcproxy import config
# from kdcproxy.config import mit


class KDCProxyWSGITests(unittest.TestCase):
    def setUp(self):  # noqa
        self.app = TestApp(kdcproxy.application)

    def test_get(self):
        r = self.app.get('/', expect_errors=True)
        self.assertEqual(r.status_code, 405)
        self.assertEqual(r.status, '405 Method Not Allowed')
        self.assertEqual(r.text, 'Method not allowed (GET).')


if __name__ == "__main__":
    unittest.main()
