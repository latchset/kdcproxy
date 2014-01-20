Welcome to kdcproxy!
=====================

This package contains a WSGI module for proxying KDC requests over HTTP by
following the [MS-KKDCP] protocol. It aims to be simple to deploy, with
minimal configuration.

Deploying kdcproxy
------------------

The kdcproxy module follows the standard WSGI protocol for deploying Python
web applications. This makes configuration simple. Simply load up your favorite
WSGI-enabled web server and point it to the module. For example, if you wish
to use mod_wsgi, try something like this:

    WSGIScriptAlias /kdc /path/to/kdcproxy/__init__.py

For more information, see the documentation of your WSGI server.

Configuring kdcproxy
--------------------
When kdcproxy receives a request, it needs to know where to proxy it to. The
remote KDC is configured in two ways, both using your existing krb5
configuration file, usually /etc/krb5.conf.

First, you can manually specify realm configuration. This is done using the
format outlined [here][krb5-rlm].

Second, if a realm is not manually configured, kdcproxy can find this
configuration using DNS as described [here][krb5-dns]. In this case, kdc proxy
will look in the *[libdefaults]* section and will respect the values of
*dns_fallback* and *dns_lookup_kdc* as defined [here][krb5-cfg]. If neither
values are defined, DNS fallback mode is enabled by default.

For more information, see the documentation for your krb5 implementation.

[MS-KKDCP]: http://msdn.microsoft.com/en-us/library/hh553774.aspx
[krb5-dns]: http://web.mit.edu/kerberos/krb5-1.6/krb5-1.6.3/doc/krb5-admin.html#Using-DNS
[krb5-cfg]: http://web.mit.edu/kerberos/krb5-1.6/krb5-1.6.3/doc/krb5-admin.html#libdefaults
[krb5-rlm]: http://web.mit.edu/kerberos/krb5-1.6/krb5-1.6.3/doc/krb5-admin.html#realms-_0028krb5_002econf_0029