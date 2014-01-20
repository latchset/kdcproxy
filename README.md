Welcome to kdcproxy!
=====================

This package contains a WSGI module for proxying KDC requests over HTTP by
following the [MS-KKDCP] protocol. It aims to be simple to deploy, with
minimal configuration.

Deploying kdcproxy
==================

The kdcproxy module follows the standard WSGI protocol for deploying Python
web applications. This makes configuration simple. Simply load up your favorite
WSGI-enabled web server and point it to the module. For example, if you wish
to use mod_wsgi, try something like this:

    WSGIScriptAlias /kdc /path/to/kdcproxy/__init__.py

For more information, see the documentation of your WSGI server.

Configuring kdcproxy
====================

When kdcproxy receives a request, it needs to know where to proxy it to. This
is the purpose of configuration: discovering where to send kerberos requests.

Automatic Configuration
-----------------------
By default, no configuration is necessary. In this case, kdcproxy will use
REALM DNS SRV record lookups to determine remote KDC locations.

/etc/kdcproxy.conf
------------------
If you wish to have more detailed configuration, the first place you can
configure kdcproxy is /etc/kdcproxy.conf. This configuration file takes precedence
over all other configuration modules. This file is an ini-style configuration with
a special section *[global]*. Two parameters are available in this
section: *configs* and *use_dns*.

The *use_dns* allows you to enable or disable use of DNS SRV record lookups.

The *configs* parameter allows you to load other configuration modules for finding
configuration in other places. The configuration modules specified in here will
have priority in the order listed. For instance, if you wished to read configuration
from MIT libkrb5, you would set the following:

    [global]
    configs = mit

Aside from the *[global]* section, you may also specify manual configuration for
realms. In this case, each section is the name of the realm and the parameters are
*kerberos* or *kpasswd*. These specify the locations of the remote servers for
krb5 AS requests and kpasswd requests, respectively. For example:

    [EXAMPLE.COM]
    kerberos = kerberos+tcp://kdc.example.com:88
    kpasswd = kpasswd+tcp://kpasswd.example.com:464

The realm configuration parameters may list multiple servers separate by a space.
Leaving off the "+tcp" or "+udp" will result in both protocols being attempted. In
this case, kdcproxy will attempt TCP connections first so that longer timeouts can
be utilized. This also prevents possible lockouts when the KDC packets contain OTP
token codes (which should preferably be sent to only one server). The port number
is entirely optional.

MIT libkrb5
-----------

If you load the *mit* config module in /etc/kdcproxy.conf, kdcproxy will also read
the config using libkrb5 (usually /etc/krb5.conf). If this module is used, kdcproxy
will respect the DNS settings from the *[libdefaults]* section and the realm
configuration from the *[realms]* section.

For more information, see the documentation for MIT's krb5.conf.

[MS-KKDCP]: http://msdn.microsoft.com/en-us/library/hh553774.aspx

