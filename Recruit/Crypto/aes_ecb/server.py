import SocketServer
import socket
from Crypto.Cipher import AES
from struct import pack, unpack

from secret import AES_KEY, FLAG


def split_by(data, step):
    return [data[i:i + step] for i in range(0, len(data), step)]


def pad(msg):
    byte = 16 - len(msg) % 16
    return msg + chr(0) * byte


def encrypt(aes, msg):
    return aes.encrypt(pad(msg))


def send_binary(req, msg):
    req.sendall('{0:04d}'.format(len(msg)))
    send_msg(req, msg)


def send_enc(req, aes, msg):
    send_binary(req, encrypt(aes, msg))


def send_msg(req, msg):
    req.sendall(msg)


def recv_exact(req, length):
    buf = ''
    while length > 0:
        data = req.recv(length)
        if data == '':
            raise EOFError()
        buf += data
        length -= len(data)
    return buf


def recv_msg(req):
    size = recv_exact(req, 4)
    size = int(size)
    return recv_exact(req, size)


def recv_option(req):
    return int(recv_exact(req, 1))


def main(req):
    aes = AES.new(AES_KEY, AES.MODE_ECB)
    try:
        while True:
            option = recv_option(req)
            if option == 0:
                req.sendall('Send me text and I\'ll give it back encrypted\n')
                plaintext = recv_msg(req)
                send_enc(req, aes, plaintext)
            elif option == 1:
                req.sendall('Get the Flag\n')
                pad = recv_msg(req)
                send_enc(req, aes, pad + FLAG)
            elif option == 2:
                req.sendall('Bye\n')
                break
    except EOFError:
        pass


class TaskHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        main(self.request)


if __name__ == '__main__':
    SocketServer.ThreadingTCPServer.allow_reuse_address = True
    server = SocketServer.ThreadingTCPServer(('0.0.0.0', 1337), TaskHandler)
    server.serve_forever()
