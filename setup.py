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
import sys
from distutils.core import setup

dns = "dnspython"
if sys.version_info.major == 3:
    dns += "3"


def read(fname):
    fname = os.path.join(os.path.dirname(__file__), fname)
    with open(fname) as f:
        return f.read()

setup(
    name="kdcproxy",
    version="0.3.2",
    author="Nalin Dahyabhai, Nathaniel McCallum, Christian Heimes",
    author_email="nalin@redhat.com, npmccallum@redhat.com, cheimes@redhat.com",
    description=("A kerberos KDC HTTP proxy WSGI module."),
    license="MIT",
    keywords="krb5 proxy http https kerberos",
    url="http://github.com/npmccallum/kdcproxy",
    packages=['kdcproxy', 'kdcproxy.config'],
    long_description=read('README'),
    requires=['pyasn1', dns],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Topic :: Internet :: Proxy Servers",
    ],
)
