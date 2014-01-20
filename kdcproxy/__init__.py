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

from kdcproxy.config import MetaResolver
import kdcproxy.codec

import socket

try: # Python 3.x
    import http.client as httplib
    import urllib.parse as urlparse
except ImportError: # Python 2.x
    import httplib
    import urlparse

class HTTPException(Exception):
    def __init__(self, code, msg, headers=[]):
        headers = filter(lambda h: h[0] != 'Content-Length', headers)
        headers.append(('Content-Length', str(len(msg))))

        if 'Content-Type' not in dict(headers):
            headers.append(('Content-Type', 'text/plain'))

        super(HTTPException, self).__init__(msg)
        self.code = code
        self.headers = headers

    def __str__(self):
        return "%d %s" % (self.code, httplib.responses[self.code])

class Application:
    def __init__(self):
        self.__resolver = MetaResolver()

    def __call__(self, env, start_response):
        try:
            # Validate the method
            method = env["REQUEST_METHOD"].upper()
            if method != "POST":
                raise HTTPException(405, "Method not allowed (%s)." % method,
                                    ("Allow", "POST"))

            # Parse the request
            try:
                pr = codec.decode(env["wsgi.input"].read())
            except codec.ParsingError as e:
                raise HTTPException(400, e.message)

            # Find the remote proxy
            servers = self.__resolver.lookup(pr.realm,
                                  isinstance(pr, codec.KPASSWDProxyRequest))
            if not servers:
                raise HTTPException(503, "Can't find remote (%s)." % pr)

            # Connect to the remote server
            for server in map(urlparse.urlparse, servers):
                if server.scheme.lower() not in ("kerberos+tcp", "kpasswd+tcp"):
                    continue

                for af in (socket.AF_INET6, socket.AF_INET):
                    sock = socket.socket(af, socket.SOCK_STREAM)
                    try:
                        sock.connect((server.hostname, server.port))
                        break
                    except socket.gaierror:
                        sock.close()
                        sock = None
                if sock:
                    break
            if not sock:
                raise HTTPException(503, "Can't connect to remote (%s)." % pr)

            # Send the request to the remote server
            try:
                sock.sendall(pr.request)
                reply = sock.recv(1048576)
            finally:
                sock.close()

            # Return the result to the client
            raise HTTPException(200, codec.encode(reply),
                                [("Content-Type", "application/kerberos")])
        except HTTPException as e:
            start_response(str(e), e.headers)
            return [e.message]

if __name__ == "__main__":
    application = Application()
