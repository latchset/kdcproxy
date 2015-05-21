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

import ctypes
import sys

try:
    import urllib.parse as urlparse
except ImportError:  # pragma: no cover
    import urlparse

from kdcproxy.config import IConfig


class KRB5Error(Exception):
    pass

PY3 = sys.version_info[0] == 3

try:
    LIBKRB5 = ctypes.CDLL('libkrb5.so.3')
except OSError as e:  # pragma: no cover
    LIBKRB5 = e
else:
    class c_text_p(ctypes.c_char_p):  # noqa
        """A c_char_p variant that can handle UTF-8 text"""
        @classmethod
        def from_param(cls, value):
            if value is None:
                return None
            if PY3 and isinstance(value, str):
                return value.encode('utf-8')
            elif not PY3 and isinstance(value, unicode):  # noqa
                return value.encode('utf-8')
            elif not isinstance(value, bytes):
                raise TypeError(value)
            else:
                return value

        @property
        def text(self):
            value = self.value
            if value is None:
                return None
            elif not isinstance(value, str):
                return value.decode('utf-8')
            return value

    class _krb5_context(ctypes.Structure):  # noqa
        """krb5/krb5.h struct _krb5_context"""
        __slots__ = ()
        _fields_ = []

    class _profile_t(ctypes.Structure):  # noqa
        """profile.h struct _profile_t"""
        __slots__ = ()
        _fields_ = []

    def krb5_errcheck(result, func, arguments):
        """Error checker for krb5_error return value"""
        if result != 0:
            raise KRB5Error(result, func.__name__, arguments)

    krb5_context = ctypes.POINTER(_krb5_context)
    profile_t = ctypes.POINTER(_profile_t)
    iter_p = ctypes.c_void_p
    krb5_error = ctypes.c_int32

    krb5_init_context = LIBKRB5.krb5_init_context
    krb5_init_context.argtypes = (ctypes.POINTER(krb5_context), )
    krb5_init_context.restype = krb5_error
    krb5_init_context.errcheck = krb5_errcheck

    krb5_free_context = LIBKRB5.krb5_free_context
    krb5_free_context.argtypes = (krb5_context, )
    krb5_free_context.retval = None

    krb5_get_profile = LIBKRB5.krb5_get_profile
    krb5_get_profile.argtypes = (krb5_context, ctypes.POINTER(profile_t))
    krb5_get_profile.restype = krb5_error
    krb5_get_profile.errcheck = krb5_errcheck

    profile_release = LIBKRB5.profile_release
    profile_release.argtypes = (profile_t, )
    profile_release.restype = None

    profile_iterator_create = LIBKRB5.profile_iterator_create
    profile_iterator_create.argtypes = (profile_t,
                                        ctypes.POINTER(c_text_p),
                                        ctypes.c_int,
                                        ctypes.POINTER(iter_p))
    profile_iterator_create.restype = krb5_error
    profile_iterator_create.errcheck = krb5_errcheck

    profile_iterator_free = LIBKRB5.profile_iterator_free
    profile_iterator_free.argtypes = (ctypes.POINTER(iter_p), )
    profile_iterator_free.retval = None

    profile_iterator = LIBKRB5.profile_iterator
    profile_iterator.argtypes = (ctypes.POINTER(iter_p),
                                 ctypes.POINTER(c_text_p),
                                 ctypes.POINTER(c_text_p))
    profile_iterator.restype = krb5_error
    profile_iterator.errcheck = krb5_errcheck

    profile_get_boolean = LIBKRB5.profile_get_boolean
    profile_get_boolean.argtypes = (profile_t,
                                    c_text_p,
                                    c_text_p,
                                    c_text_p,
                                    ctypes.c_int,
                                    ctypes.POINTER(ctypes.c_int))
    profile_get_boolean.restype = krb5_error
    profile_get_boolean.errcheck = krb5_errcheck


class KRB5Profile:

    class Iterator:
        def __init__(self, profile, *args):
            # Convert string arguments to UTF8 bytes
            args = [c_text_p.from_param(arg) for arg in args]
            args.append(None)
            # Create array
            array = c_text_p * len(args)
            self.__path = array(*args)
            # Call the function
            self.__iterator = iter_p()
            profile_iterator_create(profile,
                                    self.__path,
                                    1,
                                    ctypes.byref(self.__iterator))

        def __iter__(self):
            return self

        def __next__(self):
            try:
                name = c_text_p()
                value = c_text_p()
                profile_iterator(ctypes.byref(self.__iterator),
                                 ctypes.byref(name),
                                 ctypes.byref(value))
                if not name.value:
                    raise KRB5Error
                return name.text, value.text
            except KRB5Error:
                profile_iterator_free(ctypes.byref(self.__iterator))
                self.__iterator = None
                raise StopIteration()

        def __del__(self):
            if self.__iterator:  # pragma: no cover
                profile_iterator_free(ctypes.byref(self.__iterator))
                self.__iterator = None

        # Handle iterator API change
        if not PY3:
            next = __next__

    def __init__(self):
        self.__context = self.__profile = None
        if isinstance(LIBKRB5, Exception):  # pragma: no cover
            raise LIBKRB5
        context = krb5_context()
        krb5_init_context(ctypes.byref(context))
        self.__context = context
        profile = profile_t()
        krb5_get_profile(context, ctypes.byref(profile))
        self.__profile = profile

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self.__context:
            krb5_free_context(self.__context)
            self.__context = None
        if self.__profile:
            profile_release(self.__profile)
            self.__profile = None

    def __del__(self):
        self.__exit__(None, None, None)

    def __getitem__(self, name):
        return self.section(name)

    def get_bool(self, name, subname=None, subsubname=None, default=False):
        val = ctypes.c_int(1)
        profile_get_boolean(self.__profile,
                            name, subname, subsubname,
                            int(default), ctypes.byref(val))
        return bool(val.value)

    def section(self, *args):
        output = []

        for k, v in KRB5Profile.Iterator(self.__profile, *args):
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
            if "dns_lookup_kdc" in dict(prof.section("libdefaults")):
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
            servers = list(rconf.get('kpasswd_server', []))
            servers.extend(rconf.get('admin_server', []))
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
