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

import io
import logging
import select
import socket
import struct
import sys
import time

try:  # Python 3.x
    import http.client as httplib
    import urllib.parse as urlparse
except ImportError:  # Python 2.x
    import httplib
    import urlparse

import kdcproxy.codec as codec
from kdcproxy.config import MetaResolver


class HTTPException(Exception):

    def __init__(self, code, msg, headers=[]):
        headers = list(filter(lambda h: h[0] != 'Content-Length', headers))

        if 'Content-Type' not in dict(headers):
            headers.append(('Content-Type', 'text/plain; charset=utf-8'))

        if sys.version_info.major == 3 and isinstance(msg, str):
            msg = bytes(msg, "utf-8")

        headers.append(('Content-Length', str(len(msg))))

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
        extra = 0
        read_buffers = {}
        while (timeout + extra) > time.time():
            if not wsocks and not rsocks:
                break

            r, w, x = select.select(rsocks, wsocks, rsocks + wsocks,
                                    (timeout + extra) - time.time())
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
                    if self.sock_type(sock) == socket.SOCK_DGRAM:
                        # If we proxy over UDP, remove the 4-byte length
                        # prefix since it is TCP only.
                        sock.sendall(pr.request[4:])
                    else:
                        sock.sendall(pr.request)
                        extra = 10  # New connections get 10 extra seconds
                except Exception:
                    logging.exception('Error in recv() of %s', sock)
                    continue
                rsocks.append(sock)
                wsocks.remove(sock)

            for sock in r:
                try:
                    reply = self.__handle_recv(sock, read_buffers)
                except Exception:
                    logging.exception('Error in recv() of %s', sock)
                    if self.sock_type(sock) == socket.SOCK_STREAM:
                        # Remove broken TCP socket from readers
                        rsocks.remove(sock)
                else:
                    if reply is not None:
                        return reply

        return None

    def __handle_recv(self, sock, read_buffers):
        if self.sock_type(sock) == socket.SOCK_DGRAM:
            # For UDP sockets, recv() returns an entire datagram
            # package. KDC sends one datagram as reply.
            reply = sock.recv(1048576)
            # If we proxy over UDP, we will be missing the 4-byte
            # length prefix. So add it.
            reply = struct.pack("!I", len(reply)) + reply
            return reply
        else:
            # TCP is a different story. The reply must be buffered
            # until the full answer is accumulated.
            buf = read_buffers.get(sock)
            part = sock.recv(1048576)
            if buf is None:
                if len(part) > 4:
                    # got enough data in the initial package. Now check
                    # if we got the full package in the first run.
                    (length, ) = struct.unpack("!I", part[0:4])
                    if length + 4 == len(part):
                        return part
                read_buffers[sock] = buf = io.BytesIO()

            if part:
                # data received, accumulate it in a buffer
                buf.write(part)
                return None
            else:
                # EOF received
                read_buffers.pop(sock)
                reply = buf.getvalue()
                return reply

    def __filter_addr(self, addr):
        if addr[0] not in (socket.AF_INET, socket.AF_INET6):
            return False

        if addr[1] not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            return False

        if addr[2] not in (socket.IPPROTO_TCP, socket.IPPROTO_UDP):
            return False

        return True

    def sock_type(self, sock):
        try:
            return sock.type & ~socket.SOCK_NONBLOCK
        except AttributeError:
            return sock.type

    def __call__(self, env, start_response):
        try:
            # Validate the method
            method = env["REQUEST_METHOD"].upper()
            if method != "POST":
                raise HTTPException(405, "Method not allowed (%s)." % method)

            # Parse the request
            try:
                length = int(env["CONTENT_LENGTH"])
            except AttributeError:
                length = -1
            try:
                pr = codec.decode(env["wsgi.input"].read(length))
            except codec.ParsingError as e:
                raise HTTPException(400, e.message)

            # Find the remote proxy
            servers = self.__resolver.lookup(
                pr.realm,
                kpasswd=isinstance(pr, codec.KPASSWDProxyRequest)
            )
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
                addrs = tuple(sorted(filter(self.__filter_addr, addrs)))
                for addr in addrs + (None,):
                    if addr is not None:
                        # Bypass unspecified socktypes
                        if (len(scheme) > 1
                                and addr[1] != self.SOCKTYPES[scheme[1]]):
                            continue

                        # Create the socket
                        sock = socket.socket(*addr[:3])
                        sock.setblocking(0)

                        # Connect
                        try:
                            # In Python 2.x, non-blocking connect() throws
                            # socket.error() with errno == EINPROGRESS. In
                            # Python 3.x, it throws io.BlockingIOError().
                            sock.connect(addr[4])
                        except socket.error as e:
                            if e.errno != 115:  # errno != EINPROGRESS
                                sock.close()
                                continue
                        except io.BlockingIOError:
                            pass
                        wsocks.append(sock)

                    # Resend packets to UDP servers
                    for sock in tuple(rsocks):
                        if self.sock_type(sock) == socket.SOCK_DGRAM:
                            wsocks.append(sock)
                            rsocks.remove(sock)

                    # Call select()
                    timeout = time.time() + (15 if addr is None else 2)
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

application = Application()
