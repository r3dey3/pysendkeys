#!/usr/bin/env python


import array
import argparse
import fcntl
import os
import pty
import select
import signal
import sys
import termios
import tty
import time
import socket
import json
import struct


KEY_CMD = 1
START_CMD = 2
LOG = True
def log(s):
    if LOG:
        with open("log", "a") as f:
            f.write("%s\n" % str(s))


def os_write_all(fd, data):
    assert fd is not None
    while data != '':
        n = os.write(fd, data)
        data = data[n:]

class PtyServer(object):
    def __init__(self):
        pass
    
    def _open_server(self, ip, port):
        self.srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.srv_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self.srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv_sock.setblocking(0)
        self.srv_sock.bind((ip, port))
        self.srv_sock.listen(5)
        log("server fd = %d" % self.srv_sock.fileno())
        self.ep.register(self.srv_sock.fileno(), select.EPOLLIN)
        self.clients = {}
        self.client_bufs = {}

    def _handle_sigwinch(self, signum, frame):
        self.set_pty_size()

    def _setup(self):
        self.old_handler = signal.signal(signal.SIGWINCH, self._handle_sigwinch)
        try:
            self.orig_ttymode = tty.tcgetattr(pty.STDIN_FILENO)
            tty.setraw(pty.STDIN_FILENO)
            self.restore_tty = True
        except tty.error:
            self.restore_tty = False

        self.ep = select.epoll()
        self.ep.register(pty.STDIN_FILENO, select.EPOLLIN)

    def _cleanup(self):
        if self.restore_tty:
            tty.tcsetattr(pty.STDIN_FILENO, tty.TCSAFLUSH, self.orig_ttymode)
        signal.signal(signal.SIGWINCH, self.old_handler)
   
    def _set_pty_size():
        buf = array.array('h', [0, 0, 0, 0])
        fcntl.ioctl(pty.STDOUT_FILENO, termios.TIOCGWINSZ, buf, True)
        if self.master_fd is not None:
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, buf)

    def start_process(self, *command):
        command = self.command or command
        if command is None:
            print "Error"
            return
        self.child_pid, self.master_fd = pty.fork()
        if self.child_pid == pty.CHILD:
            os.execlp(command[0], *command)
            sys.exit(0)

        self.ep.register(self.master_fd, select.EPOLLIN)


    def _handle_accept(self):
        conn, addr = self.srv_sock.accept()
        conn.setblocking(0)
        self.ep.register(conn.fileno(), select.EPOLLIN)
        self.clients[conn.fileno()] = conn
        self.client_bufs[conn] = ""
        

    def _handle_client_command(self, command, args):
        if command == "send-keys":
            log("sending %r" % args)
            os_write_all(self.master_fd, args)
        elif command == "run":
            self.start_process(args)

    def _handle_client_data(self, fd, event):
        conn = self.clients[fd]
        cur_buf = self.client_bufs[conn]
        new_buf = conn.recv(1)
        if new_buf == "":
            self.ep.unregister(fd)
            conn.close()
            return
        cur_buf += new_buf
        self._handle_client_command("send-keys", cur_buf)
        cur_buf = ""
        self.client_bufs[conn] = cur_buf
    
    def run(self, args):
        self.command = args.command or ["/bin/cat"]
        self.master_fd = None

        self._setup()
        self._open_server(args.ip, args.port)

        self.start_process(self.command)
        try:
            done = False
            while not done:
                events = self.ep.poll()
                log("Events %r" % events)
                for fd, event in events:
                    if event == select.EPOLLHUP:
                        done = True
                    if fd == self.master_fd:
                        data = os.read(fd, 4096)
                        os_write_all(pty.STDOUT_FILENO, data)
                        log("FROM CHILD-> %r"  % data)
                    elif fd == pty.STDIN_FILENO:
                        data = os.read(fd, 4096)
                        log("TO CHILD-> %r"  % data)
                        if self.master_fd is None:
                            if data == "\x03":
                                done = True
                        else:
                            os_write_all(self.master_fd, data)
                    elif fd == self.srv_sock.fileno():
                        log("New client")
                        self._handle_accept()
                    else:
                        self._handle_client_data(fd, event)
        except (IOError, OSError):
            pass
        finally:
            self._cleanup()

class PtyClient(object):
    def __init__(self):
        pass

    def connect(self, dst, port):
        try:
            self.sock = socket.socket(socket.AF_INET6 if ':' in dst else socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((dst, port))
        except socket.error, e:
            print "Error: %s" % repr(e)
            exit(1)

class SendKeys(PtyClient):
    def __init__(self):
        pass

    def run(self, args):
        self.connect(args.ip, args.port)
        for k in args.keys:
            self.send_key(k, args.expand)

    def send_key(self, key, expand=True):
        if expand:
            meta = ""
            key_up = key.upper()
            if key_up.startswith("M-"):
                meta = "\x1b"
                key = key[2:]
            if key_up.startswith("C-") and len(key) == 3:
                k = key_up[2]
                if k in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                    key = chr(ord(k) - ord('A') + 1)
            elif key.startswith("^") and len(key) == 2:
                k = key_up[1]
                if k in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                    key = chr(ord(k) - ord('A') + 1)
            if key_up == "ESCAPE":
                key = "\x1b"
            elif key_up == "HOME":
                key = "\x1b[1~"
            elif key_up == "END":
                key = "\x1b[4~"
            elif key_up == "PGUP": #PPage PageUp
                key = "\x1b[5~"
            elif key_up == "PGDN": #NPage PageDown
                key = "\x1b[6~"

            mapping = {
                    "BSPACE": "",
                    "BTAB": "",
                    "DC": "",  #Delete Char
                    "ENTER": "",
                    "IC": "", #Insert Char
                    "SPACE": "",
                    "TAB": "",
                    "ENTER": "",
                    "UP": "",
                    "DOWN": "",
                    "LEFT": "",
                    "RIGHT": "",
            }
            # F1-F20
            # C-SPACe
            # C-LEFT C-RIGHT C-DOWN C-UP
            

            key = meta + key
        self.sock.send(key)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", dest="port", default=14412)
    parser.add_argument("-i", "--ip", dest="ip", default="localhost")

    subparsers = parser.add_subparsers(dest="action", title="Action")

    server_parser=subparsers.add_parser('server', help="Server mode")
    server_parser.add_argument("command", metavar="COMMAND [ARGUMENTS ...]", nargs=argparse.REMAINDER)
    server_parser.set_defaults(cls=PtyServer)

    sk_parser =subparsers.add_parser('send-keys', help="Send-keys mode")
    sk_parser.add_argument("-l", help="Disable key name lookup", dest="expand", action="store_const", const=False, default=True)
    sk_parser.add_argument("keys", metavar="keys [keys ...]", nargs=argparse.REMAINDER)
    sk_parser.set_defaults(cls=SendKeys)

    args = parser.parse_args()
    obj = args.cls()
    obj.run(args)

    sys.exit(0)
