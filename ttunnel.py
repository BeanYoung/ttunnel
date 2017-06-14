#!/usr/bin/python
# -*- coding: utf-8 -*-

from hashlib import md5

from Crypto.Cipher import AES
from tornado.ioloop import IOLoop
from tornado.gen import coroutine
from tornado.log import app_log
from tornado.tcpclient import TCPClient
from tornado.tcpserver import TCPServer
from tornado.options import define, options, parse_command_line


class Tunnel(TCPServer):
    def __init__(self, secret, client_mode, backend):
        super(Tunnel, self).__init__()
        self.secret = md5(secret).hexdigest()
        self.client_mode = client_mode
        self.backend_host = backend.split(':')[0]
        self.backend_port = int(backend.split(':')[1])

    @coroutine
    def handle_stream(self, stream, address):
        backend = yield TCPClient().connect(
            self.backend_host, self.backend_port)
        ec = AES.new(self.secret, AES.MODE_CFB, self.secret[:16])
        dc = AES.new(self.secret, AES.MODE_CFB, self.secret[:16])
        if self.client_mode:
            stream.read_until_close(
                streaming_callback=self.pipe(stream, backend, ec.encrypt))
            backend.read_until_close(
                streaming_callback=self.pipe(backend, stream, dc.decrypt))
        else:
            stream.read_until_close(
                streaming_callback=self.pipe(stream, backend, dc.decrypt))
            backend.read_until_close(
                streaming_callback=self.pipe(backend, stream, ec.encrypt))

    def pipe(self, f, t, p=None):
        fa = f.socket.getpeername()
        ta = f.socket.getpeername()

        def process_data(data):
            app_log.info('from %(from)s to %(to)s: %(size)d' % {
                'from': fa,
                'to': ta,
                'size': len(data),
            })
            if p:
                t.write(p(data))
            else:
                t.write(data)

            if f.closed():
                t.close()
        return process_data


if __name__ == '__main__':
    define('secret', default='', help='password used to encrypt the data')
    define('client-mode', default=False, help='if running at client mode')
    define('listen', default=':9001', help='host:port ttunnel listen on')
    define(
        'backend', default='127.0.0.1:6400', help='host:port of the backend')
    parse_command_line()

    t = Tunnel(options.secret, options.client_mode, options.backend)
    t.listen(int(options.listen.split(':')[1]), options.listen.split(':')[0])
    IOLoop.current().start()
