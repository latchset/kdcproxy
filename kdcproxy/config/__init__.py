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
import logging
import os

try:  # Python 3.x
    import configparser
except ImportError:  # Python 2.x
    import ConfigParser as configparser

import dns.rdatatype
import dns.resolver

logging.basicConfig()
logger = logging.getLogger('kdcproxy')

SRV_KRB = 'kerberos'
SRV_KPWD = 'kpasswd'
SRV_KPWD_ADM = 'kerberos-adm'


class IResolver(object):

    def lookup(self, realm, kpasswd=False):
        # type: (str, bool) -> Iterable[str]
        "Returns an iterable of remote server URIs."
        raise NotImplementedError()


class IConfig(IResolver):

    def realm_configured(self, realm):
        # type: (str) -> bool
        """Check if a realm is declared in the configuration."""
        raise NotImplementedError()

    def param(self, realm, param):
        # type: (str, str) -> bool
        """Get a configuration parameter value for a realm.

        None can be passed as realm to query global parameters only.
        """
        raise NotImplementedError()


class KDCProxyConfig(IConfig):
    GLOBAL = "global"
    default_filenames = ["/usr/local/etc/kdcproxy.conf", "/etc/kdcproxy.conf"]

    GLOBAL_PARAMS = {
        'dns_realm_discovery': False,
    }
    GENERAL_PARAMS = {
        'use_dns': True,
        'silence_port_warn': False,
    }
    RESOLV_PARAMS = [SRV_KRB, SRV_KPWD]

    @staticmethod
    def __get_cfg_param(cp, section, param, typ):
        """Retrieve a typed parameter from a configuration section."""
        try:
            if typ is bool:
                return cp.getboolean(section, param)
            elif typ is str:
                return cp.get(section, param)
            else:
                raise ValueError(
                    'Configuration parameters cannot have "%s" type' %
                    typ.__name__)
        except configparser.Error:
            return None

    def __init__(self, filenames=None):
        cp = configparser.ConfigParser()
        if filenames is None:
            filenames = os.environ.get("KDCPROXY_CONFIG", None)
        if filenames is None:
            filenames = self.default_filenames
        try:
            cp.read(filenames)
        except configparser.Error:
            logger.error("Unable to read config file(s): %s", filenames)

        try:
            mod = cp.get(self.GLOBAL, "configs")
            try:
                importlib.import_module("kdcproxy.config." + mod)
            except ImportError as e:
                logger.log(logging.ERROR, "Error reading config: %s" % e)
        except configparser.Error:
            pass

        self.__config = dict()

        for section in cp.sections():
            self.__config.setdefault(section, {})
            for param in self.GENERAL_PARAMS.keys():
                value = self.__get_cfg_param(cp, section, param, bool)
                if value is not None:
                    self.__config[section][param] = value
            if section == self.GLOBAL:
                for param in self.GLOBAL_PARAMS.keys():
                    value = self.__get_cfg_param(cp, section, param, bool)
                    if value is not None:
                        self.__config[section][param] = value
            elif not section.startswith('*'):
                for service in self.RESOLV_PARAMS:
                    servers = self.__get_cfg_param(cp, section, service, str)
                    if servers:
                        self.__config[section][service] = (
                            tuple(servers.split())
                        )

    def __global_forbidden(self, realm):
        """Raise ValueError if realm name is 'global'."""
        if realm == self.GLOBAL:
            raise ValueError('"%s" is not allowed as realm name' % realm)

    def lookup(self, realm, kpasswd=False):
        self.__global_forbidden(realm)
        service = SRV_KPWD if kpasswd else SRV_KRB
        if realm in self.__config and service in self.__config[realm]:
            return self.__config[realm][service]
        else:
            return ()

    def realm_configured(self, realm):
        """Check if a realm is declared in the configuration.

        Matches exact realm sections or wildcard realm sections.
        """
        self.__global_forbidden(realm)

        if realm in self.__config:
            return True

        realm_labels = realm.split('.')
        for i in range(len(realm_labels)):
            rule = '*' + '.'.join(realm_labels[i:])
            if rule in self.__config:
                return True

        return False

    def param(self, realm, param):
        """Get a configuration parameter value for a realm.

        None can be passed as realm to query global parameters only.
        Precedence: exact realm, wildcard realm, global, default.
        """
        self.__global_forbidden(realm)

        if realm is not None:
            if param in self.__config.get(realm, {}):
                # Parameter found in realm section
                return self.__config[realm][param]

            realm_labels = realm.split('.')
            for i in range(len(realm_labels)):
                rule = '*' + '.'.join(realm_labels[i:])
                if param in self.__config.get(rule, {}):
                    # Parameter found in realm matching rule
                    return self.__config[rule][param]

        if param in self.__config.get(self.GLOBAL, {}):
            # Fallback to global section
            return self.__config[self.GLOBAL][param]

        if param in self.GENERAL_PARAMS:
            # Fallback to default value if general parameter not set
            return self.GENERAL_PARAMS[param]

        if param in self.GLOBAL_PARAMS:
            # Fallback to default value if global parameter not set
            return self.GLOBAL_PARAMS[param]

        raise ValueError('Configuration parameter "%s" does not exist' % param)


class DNSResolver(IResolver):

    def __init__(self, log_warning=None):
        self.__log_warning = log_warning

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
        service = SRV_KPWD if kpasswd else SRV_KRB

        for protocol in ("tcp", "udp"):
            sv = service
            servers = tuple(self.__dns(sv, protocol, realm))
            if not servers and kpasswd:
                sv = SRV_KPWD_ADM
                servers = self.__dns(sv, protocol, realm)

            for host, port in servers:
                if self.__log_warning:
                    self.__log_warning(sv, protocol, realm, kpasswd, host,
                                       port)
                yield "%s://%s:%d" % (service, host, port)


class MetaResolver(IResolver):

    STANDARD_PORTS = {SRV_KRB: 88, SRV_KPWD: 464}

    def __init__(self):
        self.__config = KDCProxyConfig()
        self.__dns_resolver = DNSResolver(self.__log_warning)
        self.__extra_configs = []
        for cfgcls in IConfig.__subclasses__():
            if cfgcls is KDCProxyConfig:
                continue
            try:
                self.__extra_configs.append(cfgcls())
            except Exception as e:
                logging.warning("Error instantiating %s due to %s", cfgcls,
                                repr(e))

    def __unique(self, items):
        "Removes duplicate items from an iterable while maintaining order."
        items = tuple(items)
        unique = set(items)
        for item in items:
            if item in unique:
                unique.remove(item)
                yield item

    def __silenced_port_warn(self, realm):
        """Check if port warnings are silenced for a realm."""
        return self.__config.param(realm, 'silence_port_warn')

    def __log_warning(self, service, protocol, realm, kpasswd, host, port):
        """Log a warning if a KDC uses a non-standard port."""
        if not self.__silenced_port_warn(realm):
            expected_port = self.STANDARD_PORTS[SRV_KPWD if kpasswd
                                                else SRV_KRB]
            if port != expected_port:
                logger.warning(
                    'DNS SRV record _%s._%s.%s. points to KDC %s with '
                    'non-standard port %i (%i expected)',
                    service, protocol, realm, host, port, expected_port)

    def __realm_configured(self, realm):
        """Check if realm is declared in any configuration source."""
        if self.__config.realm_configured(realm):
            return True
        for c in self.__extra_configs:
            if c.realm_configured(realm):
                return True
        return False

    def __dns_discovery_allowed(self, realm):
        """Check if DNS discovery is allowed for a realm."""
        return (
            self.__realm_configured(realm)
            or self.__config.param(None, 'dns_realm_discovery')
        ) and self.__config.param(realm, 'use_dns')

    def lookup(self, realm, kpasswd=False):
        servers = tuple(self.__unique(self.__config.lookup(realm, kpasswd)))
        if servers:
            return servers

        for c in self.__extra_configs:
            servers = tuple(self.__unique(c.lookup(realm, kpasswd)))
            if servers:
                return servers

        # The scope of realms we are allowed to use DNS discovery for depends
        # on the configuration
        if self.__dns_discovery_allowed(realm):
            servers = tuple(self.__unique(
                self.__dns_resolver.lookup(realm, kpasswd)))
            return servers

        return ()
