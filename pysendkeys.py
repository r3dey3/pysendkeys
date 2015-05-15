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




def log(s):
    with open("log", "a") as f:
        f.write("%s\n" % s)


def os_write_all(fd, data):
    assert fd is not None
    while data != '':
        n = os.write(fd, data)
        data = data[n:]


parser = argparse.ArgumentParser()
parser.add_argument("-p", "--port", dest="port", default=14412)
parser.add_argument("-i", "--ip", dest="ip", default="localhost")

subparsers = parser.add_subparsers(dest="action", title="Action")

server_parser=subparsers.add_parser('server', help="Server mode")
server_parser.add_argument("command", metavar="COMMAND [ARGUMENTS ...]", nargs=argparse.REMAINDER)


args = parser.parse_args()
print "%r" % args


class PtyServer(object):
    def __init__(self, args):
        self.command = args.command
        self.master_fd = None

        self._setup()
        self._open_server(args.ip, args.port)
    
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
    
    def run(self):
        self.start_process("/bin/cat")
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

srv=PtyServer(args)
srv.run()
sys.exit(0)

os.close(master_fd)

#import code
#code.interact(local=locals())
