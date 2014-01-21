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
import kdcproxy.codec as codec

import select
import socket
import sys
import time
import io

try: # Python 3.x
    import http.client as httplib
    import urllib.parse as urlparse
except ImportError: # Python 2.x
    import httplib
    import urlparse

class HTTPException(Exception):
    def __init__(self, code, msg, headers=[]):
        headers = list(filter(lambda h: h[0] != 'Content-Length', headers))
        headers.append(('Content-Length', str(len(msg))))

        if 'Content-Type' not in dict(headers):
            headers.append(('Content-Type', 'text/plain'))

        if sys.version_info.major == 3 and isinstance(msg, str):
            msg = bytes(msg, "UTF8")

        super(HTTPException, self).__init__(code, msg, headers)
        self.code = code
        self.message = msg
        self.headers = headers

    def __str__(self):
        return "%d %s" % (self.code, httplib.responses[self.code])

class Application:
    SOCKTYPES = {
        "tcp": socket.SOCK_STREAM,
        "udp": socket.SOCK_DGRAM,
    }

    def __init__(self):
        self.__resolver = MetaResolver()

    def __await_reply(self, pr, rsocks, wsocks, timeout):
        while timeout > time.time():
            if not wsocks and not rsocks:
                break

            r, w, x = select.select(rsocks, wsocks, rsocks + wsocks,
                                    timeout - time.time())
            for sock in x:
                sock.close()
                try:
                    rsocks.remove(sock)
                except ValueError:
                    pass
                try:
                    wsocks.remove(sock)
                except ValueError:
                    pass

            for sock in w:
                try:
                    sock.sendall(pr.request)
                except:
                    continue
                rsocks.append(sock)
                wsocks.remove(sock)

            for sock in r:
                try:
                    return sock.recv(1048576)
                except:
                    pass

        return None

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

            # Contact the remote server
            reply = None
            wsocks = []
            rsocks = []
            for server in map(urlparse.urlparse, servers):
                # Enforce valid, supported URIs
                scheme = server.scheme.lower().split("+", 1)
                if scheme[0] not in ("kerberos", "kpasswd"):
                    continue
                if len(scheme) > 1 and scheme[1] not in ("tcp", "udp"):
                    continue

                # Do the DNS lookup
                try:
                    port = server.port
                    if port is None:
                        port = scheme[0]
                    addrs = socket.getaddrinfo(server.hostname, port)
                except socket.gaierror:
                    continue

                # Sort addresses so that we get TCP first.
                #
                # Stick a None address on the end so we can get one
                # more attempt after all servers have been contacted.
                for addr in tuple(sorted(addrs)) + (None,):
                    timeout = time.time() + 15
                    if addr is not None:
                        # Bypass unspecified socktypes
                        if len(scheme) > 1 and addr[1] != self.SOCKTYPES[scheme[1]]:
                            continue

                        # Create the socket
                        sock = socket.socket(*addr[:3])
                        sock.setblocking(0)
                        if sock.type & ~socket.SOCK_NONBLOCK == socket.SOCK_STREAM:
                            timeout = time.time() + 10
                        else:
                            timeout = time.time() + 2

                        # Connect
                        try:
                            # In Python 2.x, non-blocking connect() throws
                            # socket.error() with errno == EINPROGRESS. In
                            # Python 3.x, it throws io.BlockingIOError().
                            sock.connect(addr[4])
                        except socket.error as e:
                            if e.errno != 115: # errno != EINPROGRESS
                                sock.close()
                                continue
                        except io.BlockingIOError:
                            pass
                        wsocks.append(sock)

                    # Resend packets to UDP servers
                    for sock in tuple(rsocks):
                        if sock.type & ~socket.SOCK_NONBLOCK == socket.SOCK_DGRAM:
                            wsocks.append(sock)
                            rsocks.remove(sock)

                    # Call select()
                    reply = self.__await_reply(pr, rsocks, wsocks, timeout)
                    if reply is not None:
                        break

                if reply is not None:
                    break

            for sock in rsocks + wsocks:
                sock.close()

            if reply is None:
                raise HTTPException(503, "Remote unavailable (%s)." % pr)

            # Return the result to the client
            raise HTTPException(200, codec.encode(reply),
                                [("Content-Type", "application/kerberos")])
        except HTTPException as e:
            start_response(str(e), e.headers)
            return [e.message]

if __name__ == "__main__":
    application = Application()
