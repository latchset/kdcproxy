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

from setuptools import setup

install_requires = [
    'asn1crypto>=0.23',
    'dnspython'
]

extras_require = {
    "tests": ["pytest", "coverage", "WebTest"],
    "test_pep8": ['flake8', 'flake8-import-order', 'pep8-naming']
}


def read(fname):
    fname = os.path.join(os.path.dirname(__file__), fname)
    with open(fname) as f:
        return f.read()


# in chronological order
authors = {
    "Nalin Dahyabhai": "nalin@redhat.com",
    "Nathaniel McCallum": "npmccallum@redhat.com",
    "Christian Heimes": "cheimes@redhat.com",
    "Robbie Harwood": "rharwood@redhat.com",
}
setup(
    name="kdcproxy",
    version="0.4.1",
    author=", ".join(authors.keys()),
    author_email=", ".join(authors.values()),
    description=("A kerberos KDC HTTP proxy WSGI module."),
    license="MIT",
    keywords="krb5 proxy http https kerberos",
    url="http://github.com/npmccallum/kdcproxy",
    packages=['kdcproxy', 'kdcproxy.config'],
    long_description=read('README'),
    install_requires=install_requires,
    extras_require=extras_require,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Internet :: Proxy Servers",
    ],
)
