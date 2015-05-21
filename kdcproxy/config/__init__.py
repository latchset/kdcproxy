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

import importlib
import itertools
import logging
import os

try:  # Python 3.x
    import configparser
except ImportError:  # Python 2.x
    import ConfigParser as configparser

import dns.rdatatype
import dns.resolver


class IResolver(object):

    def lookup(self, realm, kpasswd=False):
        "Returns an iterable of remote server URIs."
        raise NotImplementedError()


class IConfig(IResolver):

    def use_dns(self):
        "Returns whether or not DNS should be used. Returns None if not set."
        raise NotImplementedError()


class KDCProxyConfig(IConfig):
    GLOBAL = "global"
    default_filename = "/etc/kdcproxy.conf"

    def __init__(self, filename=None):
        self.__cp = configparser.ConfigParser()
        if filename is None:
            filename = os.environ.get("KDCPROXY_CONFIG", None)
        if filename is None:
            filename = self.default_filename
        try:
            self.__cp.read(filename)
        except configparser.Error:
            logging.error("Unable to read config file: %s", filename)

        try:
            mod = self.__cp.get(self.GLOBAL, "configs")
            try:
                importlib.import_module("kdcproxy.config." + mod)
            except ImportError as e:
                logging.log(logging.ERROR, "Error reading config: %s" % e)
        except configparser.Error:
            pass

    def lookup(self, realm, kpasswd=False):
        service = "kpasswd" if kpasswd else "kerberos"
        try:
            servers = self.__cp.get(realm, service)
            return map(lambda s: s.strip(), servers.strip().split(" "))
        except configparser.Error:
            return ()

    def use_dns(self):
        try:
            return self.__cp.getboolean(self.GLOBAL, "use_dns")
        except configparser.Error:
            return None


class DNSResolver(IResolver):

    def __dns(self, service, protocol, realm):
        query = '_%s._%s.%s' % (service, protocol, realm)

        try:
            reply = dns.resolver.query(query, dns.rdatatype.SRV)
        except dns.exception.DNSException:
            reply = []

        # FIXME: pay attention to weighting, preferably while still
        # arriving at the same answer every time, for the sake of
        # clients that are having longer conversations with servers.
        reply = sorted(reply, key=lambda r: r.priority)

        for entry in reply:
            host = str(entry.target).rstrip('.')
            yield (host, entry.port)

    def lookup(self, realm, kpasswd=False):
        service = "kpasswd" if kpasswd else "kerberos"

        for protocol in ("tcp", "udp"):
            servers = tuple(self.__dns(service, protocol, realm))
            if not servers and kpasswd:
                servers = self.__dns("kerberos-adm", protocol, realm)

            for host, port in servers:
                yield "%s://%s:%d" % (service, host, port)


class MetaResolver(IResolver):
    SCHEMES = ("kerberos", "kerberos+tcp", "kerberos+udp",
               "kpasswd", "kpasswd+tcp", "kpasswd+udp",
               "http", "https",)

    def __init__(self):
        self.__resolvers = []
        for i in itertools.count(0):
            allsub = IConfig.__subclasses__()
            if not i < len(allsub):
                break

            try:
                self.__resolvers.append(allsub[i]())
            except Exception as e:
                fmt = (allsub[i], repr(e))
                logging.log(logging.WARNING,
                            "Error instantiating %s due to %s" % fmt)
        assert self.__resolvers

        # See if we should use DNS
        dns = None
        for cfg in self.__resolvers:
            tmp = cfg.use_dns()
            if tmp is not None:
                dns = tmp
                break

        # If DNS is enabled, append the DNSResolver at the end
        if dns in (None, True):
            self.__resolvers.append(DNSResolver())

    def __unique(self, items):
        "Removes duplicate items from an iterable while maintaining order."
        items = tuple(items)
        unique = set(items)
        for item in items:
            if item in unique:
                unique.remove(item)
                yield item

    def lookup(self, realm, kpasswd=False):
        for r in self.__resolvers:
            servers = tuple(self.__unique(r.lookup(realm, kpasswd)))
            if servers:
                return servers

        return ()
