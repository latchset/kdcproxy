Welcome to kdcproxy!
====================

This package contains a WSGI module for proxying KDC requests over HTTP by
following the [MS-KKDCP] protocol. It aims to be simple to deploy, with
minimal configuration.

Deploying kdcproxy
==================

The kdcproxy module follows the standard WSGI protocol for deploying Python
web applications. This makes configuration simple. Simply load up your favorite
WSGI-enabled web server and point it to the module. For example, if you wish
to use mod_wsgi, try something like this::

    WSGIDaemonProcess kdcproxy processes=2 threads=15 maximum-requests=1000 \
        display-name=%{GROUP}
    WSGIImportScript /usr/lib/python3.6/site-packages/kdcproxy/__init__.py \
        process-group=kdcproxy application-group=kdcproxy
    WSGIScriptAlias /KdcProxy /usr/lib/python3.6/site-packages/kdcproxy/__init__.py
    WSGIScriptReloading Off

    <Location "/KdcProxy">
        Satisfy Any
        Order Deny,Allow
        Allow from all
        WSGIProcessGroup kdcproxy
        WSGIApplicationGroup kdcproxy
    </Location>

[MS-KKDCP] suggests /KdcProxy as end point. For more information, see the
documentation of your WSGI server.


Configuring kdcproxy
====================

When kdcproxy receives a request, it needs to know where to proxy it to. This
is the purpose of configuration: discovering where to send kerberos requests.

One important note: where the underlying configuration does not specify TCP or
UDP, both will be attempted. TCP will be attempted before UDP, hence setting
`udp_preference_limit = 1` is not required for kdcproxy itself (though krb5
may still need it). This permits the use of longer timeouts and prevents
possible lockouts when the KDC packets contain OTP token codes (which should
preferably be sent to only one server).

Automatic Configuration
-----------------------
By default, no configuration is necessary. In this case, kdcproxy will use
REALM DNS SRV record lookups to determine remote KDC locations.

Master Configuration File
-------------------------
If you wish to have more detailed configuration, the first place you can
configure kdcproxy is the master configuration file. This file exists at the
location specified in the environment variable KDCPROXY_CONFIG. If this
variable is unspecified, the default locations are
`/usr/local/etc/kdcproxy.conf` or `/etc/kdcproxy.conf`. This configuration
file takes precedence over all other configuration modules. This file is an
ini-style configuration with a special section **[global]**. Two parameters
are available in this section: **configs** and **use_dns**.

The **use_dns** allows you to enable or disable use of DNS SRV record lookups.

The **configs** parameter allows you to load other configuration modules for
finding configuration in other places. The configuration modules specified in
here will have priority in the order listed. For instance, if you wished to
read configuration from MIT libkrb5, you would set the following:

    [global]
    configs = mit

Aside from the **[global]** section, you may also specify manual configuration
for realms. In this case, each section is the name of the realm and the
parameters are **kerberos** or **kpasswd**. These specify the locations of the
remote servers for krb5 AS requests and kpasswd requests, respectively. For
example:

    [EXAMPLE.COM]
    kerberos = kerberos+tcp://kdc.example.com:88
    kpasswd = kpasswd+tcp://kpasswd.example.com:464

The realm configuration parameters may list multiple servers separated by a
space. The order the realms are specified in will be respected by kdcproxy when
forwarding requests. The port number is optional. Possible schemes are:

* kerberos://
* kerberos+tcp://
* kerberos+udp://
* kpasswd://
* kpasswd+tcp://
* kpasswd+udp://

MIT libkrb5
-----------

If you load the **mit** config module in the master configuration file,
kdcproxy will also read the config using libkrb5 (usually /etc/krb5.conf). If
this module is used, kdcproxy will respect the DNS settings from the
**[libdefaults]** section and the realm configuration from the **[realms]**
section.

For more information, see the documentation for MIT's krb5.conf.

Configuration reloading
-----------------------

kdcproxy reads its configurtion files when package is imported and a global
WSGI application object is instantiated. For now kdcproxy does neither
monitor its configuration files for changes nor supports runtime updates. You
have to restart the WSGI process to make modification available. With Apache
HTTP and mod_wsgi, a reload of the server also restarts all WSGI daemons.


Configuring a client for kdcproxy
=================================

HTTPS proxy support is available since Kerberos 5 release 1.13. Some
vendors have backported the feature to older versions of krb5, too. In order
to use a HTTPS proxy, simply point the kdc and kpasswd options to the proxy URL like
explained in [HTTPS proxy] configuration guide. Your ``/etc/krb5.conf`` may
look like this::

    [libdefaults]
        default_realm = EXAMPLE.COM

    [realms]
        EXAMPLE.COM = {
            http_anchors = FILE:/etc/krb5/cacert.pem
            kdc = https://kerberos.example.com/KdcProxy
            kpasswd_server = https://kerberos.example.com/KdcProxy
    }


To debug the feature, set the environment variable ``KRB5_TRACE`` to
``/dev/stdout``. When the feature is correctly configured, you should see
two POST requests in the access log of the WSGI server and a line containing
``Sending HTTPS request`` in the debug output of kinit::

    $ env KRB5_TRACE=/dev/stdout kinit user
    [1037] 1431509096.26305: Getting initial credentials for user@EXAMPLE.COM
    [1037] 1431509096.26669: Sending request (169 bytes) to EXAMPLE.COM
    [1037] 1431509096.26939: Resolving hostname kerberos.example.com
    [1037] 1431509096.34377: TLS certificate name matched "kerberos.example.com"
    [1037] 1431509096.38791: Sending HTTPS request to https 128.66.0.1:443
    [1037] 1431509096.46387: Received answer (344 bytes) from https 128.66.0.1:443
    [1037] 1431509096.46411: Terminating TCP connection to https 128.66.0.1:443
    ...

If kinit still connects to port 88/TCP or port 88/UDP, then System Security
Services Daemon's Kerberos locator plugin might override the settings in
/etc/krb5.conf. With the environment variable ``SSSD_KRB5_LOCATOR_DEBUG=1``,
kinit and sssd_krb5_locator_plugin print out additional debug information. To
disable the KDC locator feature, edit ``/etc/sssd/sssd.conf`` and set
``krb5_use_kdcinfo`` to False:

    [domain/example.com]
    krb5_use_kdcinfo = False

Don't forget to restart SSSD!

[MS-KKDCP]: http://msdn.microsoft.com/en-us/library/hh553774.aspx

[HTTPS Proxy]: http://web.mit.edu/kerberos/krb5-current/doc/admin/https.html
