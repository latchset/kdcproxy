import importlib
import itertools
import logging
import socket
import sys

try: # Python 3.x
    import configparser
    import urllib.parse as urlparse
except ImportError: # Python 2.x
    import ConfigParser as configparser
    import urlparse

import dns.resolver
import dns.rdatatype

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

    def __init__(self, file="/etc/kdcproxy.conf"):
        self.__cp = configparser.ConfigParser()
        try:
            self.__cp.read(file)
        except configparser.Error:
            logging.log(logging.ERROR, "Unable to read config file: %s" % file)

        try:
            mod = self.__cp.get(self.GLOBAL, "configs")
            try:
                importlib.import_module("kdcproxy.config." + mod)
            except ImportError as e:
                logging.log(logging.ERROR, "Error reading config: %s" % e)
        except configparser.Error:
            pass
    
    def lookup(self, realm, kpasswd=False):
        try:
            servers = self.__cp.get(realm, "kpasswd" if kpasswd else "kerberos")
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
                logging.log(logging.WARNING,
                            "Error instantiating %s due to %s" % (cls, repr(e)))
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
