#!/usr/bin/python3

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

from kdcproxy.config import IConfig

import ctypes
import sys

try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

class KRB5Profile:
    class Error(Exception): pass

    class Library:
        def __init__(self):
            self.__dll = ctypes.CDLL('libkrb5.so.3')

        def __getattr__(self, name):
            return getattr(self.__dll, name)

        def exc(self, name):
            def inner(*args):
                func = getattr(self.__dll, name)
                retval = func(*args)
                if retval != 0:
                    raise KRB5Profile.Error(retval)
            return inner

    class Iterator:
        def __init__(self, lib, profile, *args):
            self.__lib = lib

            # Convert string arguments to UTF8 bytes
            args = list(args) + [None,]
            for i in range(len(args)):
                if type(args[i]) not in (bytes, type(None)):
                    args[i] = bytes(args[i], "UTF8")

            # Create array
            array = ctypes.c_char_p * len(args)
            self.__path = array(*args)

            # Call the function
            self.__iterator = ctypes.c_void_p()
            func = self.__lib.exc("profile_iterator_create")
            func(profile, self.__path, 1, ctypes.byref(self.__iterator))

        def __iter__(self):
            return self

        def __next__(self):
            try:
                name = ctypes.c_char_p()
                value = ctypes.c_char_p()
                func = self.__lib.exc("profile_iterator")
                func(ctypes.byref(self.__iterator), ctypes.byref(name),
                     ctypes.byref(value))
                if not name.value:
                    raise KRB5Profile.Error()

                key = name.value
                if type(key) is not str:
                    key = str(key, "UTF8")

                val = value.value
                if type(val) not in (str, type(None)):
                    val = str(val, "UTF8")

                return (key, val)
            except KRB5Profile.Error:
                self.__lib.profile_iterator_free(ctypes.byref(self.__iterator))
                raise StopIteration()

        # Handle iterator API change
        if sys.version_info.major == 2:
            next = __next__

    def __init__(self):
        self.__lib = KRB5Profile.Library()

        self.__context = ctypes.c_void_p()
        func = self.__lib.exc("krb5_init_context")
        func(ctypes.byref(self.__context))

        self.__profile = ctypes.c_void_p()
        func = self.__lib.exc("krb5_get_profile")
        func(self.__context, ctypes.byref(self.__profile))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.__context:
            self.__lib.krb5_free_context(self.__context)
            self.__context = None

    def __del__(self):
        self.__exit__(None, None, None)

    def __getitem__(self, name):
        return self.section(name)

    def get_bool(self, name, subname=None, subsubname=None, default=False):
        val = ctypes.c_uint(1)
        self.__lib.exc("profile_get_boolean")(self.__profile,
                                              name, subname, subsubname,
                                              int(default), ctypes.byref(val))
        return bool(val.value)

    def section(self, *args):
        output = []

        for k, v in KRB5Profile.Iterator(self.__lib, self.__profile, *args):
            if v is None:
                tmp = args + (k,)
                output.append((k, self.section(*tmp)))
            else:
                output.append((k, v))

        return output

class MITConfig(IConfig):
    CONFIG_KEYS = ('kdc', 'admin_server', 'kpasswd_server')

    def __init__(self, *args, **kwargs):
        self.__config = {}
        with KRB5Profile() as prof:
            # Load DNS setting
            self.__config["dns"] = prof.get_bool("libdefaults",
                                                 "dns_fallback",
                                                 default=True)
            if "dns_lookup_kdc" in prof.section("libdefaults"):
                self.__config["dns"] = prof.get_bool("libdefaults",
                                                     "dns_lookup_kdc",
                                                     default=True)

            # Load all configured realms
            self.__config["realms"] = {}
            for realm, values in prof.section("realms"):
                rconf = self.__config["realms"].setdefault(realm, {})
                for server, hostport in values:
                    if server not in self.CONFIG_KEYS:
                        continue

                    parsed = urlparse.urlparse(hostport)
                    if parsed.hostname is None:
                        scheme = {'kdc': 'kerberos'}.get(server, 'kpasswd')
                        parsed = urlparse.urlparse(scheme + "://" + hostport)

                    if parsed.port is not None and server == 'admin_server':
                        hostport = hostport.split(':', 1)[0]
                        parsed = urlparse.urlparse("kpasswd://" + hostport)

                    rconf.setdefault(server, []).append(parsed.geturl())

    def lookup(self, realm, kpasswd=False):
        rconf = self.__config.get("realms", {}).get(realm, {})

        if kpasswd:
            servers  = rconf.get('kpasswd_server', [])
            servers += rconf.get('admin_server', [])
        else:
            servers = rconf.get('kdc', [])

        return tuple(servers)

    def use_dns(self, default=True):
        return self.__config["dns"]

if __name__ == "__main__":
    from pprint import pprint
    with KRB5Profile() as prof:
        conf = prof.section()
        assert conf
        pprint(conf)

    conf = MITConfig()
    for realm in sys.argv[1:]:
        kdc = conf.lookup(realm)
        assert kdc
        print("\n%s (kdc): " % realm)
        pprint(kdc)

        kpasswd = conf.lookup(realm, True)
        assert kpasswd
        print("\n%s (kpasswd): " % realm)
        pprint(kpasswd)
