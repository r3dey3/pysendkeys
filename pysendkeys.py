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

def write_user(msg):
    sys.stdout.write("\r\n" + "*" * 80 + "\r\n%s\r\n" % str(msg) + "*" * 80 + "\r\n")

class PtyServer(object):
    def __init__(self):
        self.master_fd = None
        self.child_pid = None
        self.srv_sock = None
        self.clients = {}
        self.client_bufs = {}
        pass

    def _open_server(self, ip, port):
        self.srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.srv_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self.srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv_sock.setblocking(0)
        self.srv_sock.bind((ip, port))
        self.srv_sock.listen(5)
        self.ep.register(self.srv_sock.fileno(), select.EPOLLIN)
        self.clients = {}
        self.client_bufs = {}

    def _handle_sigwinch(self, signum, frame):
        self.set_pty_size()

    def _handle_sigchild(self, signum, frame):
        os.wait()
        pass

    def _setup(self):
        signal.signal(signal.SIGCHLD, self._handle_sigchild)
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

    def start_process(self, program):
        if self.program:
            program = self.program
        if not program:
            return
        self.stop_process()
        write_user("Running %r" % (program))
        self.child_pid, self.master_fd = pty.fork()
        if self.child_pid == pty.CHILD:
            os.execlp(program[0], *program)
            sys.exit(0)
        self.ep.register(self.master_fd, select.EPOLLIN)
        log("master = %d" % self.master_fd)


    def stop_process(self, sig=signal.SIGTERM):
        self.kill_process()
        self._close_master()

    def kill_process(self, sig=signal.SIGTERM):
        log("Kill with %d" % sig)
        if self.child_pid is None:
            return
        os.kill(self.child_pid, sig)


    def _handle_accept(self):
        conn, addr = self.srv_sock.accept()
        conn.setblocking(0)
        self.ep.register(conn.fileno(), select.EPOLLIN)
        self.clients[conn.fileno()] = conn
        self.client_bufs[conn] = ""


    def _handle_client_command(self, cmd="", **kwargs):
        if cmd == u"send-key":
            key = kwargs["key"]
        elif cmd == u"run":
            program = kwargs["program"]
            self.start_process(program)
        elif cmd == u"sigterm":
            self.kill_process(signal.SIGKILL)
        elif cmd == u"sigkill":
            self.kill_process(signal.SIGTERM)


    def _handle_client_data(self, fd, event):
        conn = self.clients[fd]
        cur_buf = self.client_bufs[conn]
        new_buf = conn.recv(4096)
        if new_buf == "":
            self.ep.unregister(fd)
            conn.close()
            return
        cur_buf += new_buf
        while True:
            if len(cur_buf) < 4:
                break
            length = struct.unpack_from(">L", cur_buf)[0]
            if len(cur_buf) < length + 4:
                break
            packed = cur_buf[4:4+length]
            cur_buf = cur_buf[4+length:]
            unpacked = json.loads(packed)
            try:
                self._handle_client_command(**unpacked)
            except Exception as e:
                log("%r" % e)
                pass

        self.client_bufs[conn] = cur_buf

    def _close_master(self):
        if self.master_fd is None:
            return
        self.ep.unregister(self.master_fd)
        try:
            os.close(self.master_fd)
        except OSError:
            pass
        self.master_fd = None
        self.child_pid = None


    def _handle_bad_master(self):
        if self.master_fd is None:
            return
        self._close_master()
        write_user("Program Exited, press Ctrl+C to exit")


    def run(self, args):
        self.program = args.program
        # or ["/bin/cat"]
        self.master_fd = None


        try:
            self._setup()
            self._open_server(args.ip, args.port)
            self.start_process(self.program)

            done = False
            while not done:
                events = self.ep.poll()
                for fd, event in events:
                    if fd == self.master_fd:
                        try:
                            data = os.read(fd, 4096)
                            if len(data) != 0:
                                os_write_all(pty.STDOUT_FILENO, data)
                            else:
                                pass
                        except OSError:
                            self._handle_bad_master()
                            pass
                        if event == select.EPOLLHUP:
                            self._handle_bad_master()
                    elif fd == pty.STDIN_FILENO:
                        data = os.read(fd, 4096)
                        if self.master_fd is None:
                            if data == "\x03":
                                done = True
                        else:
                            try:
                                os_write_all(self.master_fd, data)
                            except OSError:
                                self._handle_bad_master()
                    elif fd == self.srv_sock.fileno():
                        self._handle_accept()
                    else:
                        self._handle_client_data(fd, event)
        except (IOError, OSError) as e:
            log("ERROR %r" % e)
            raise
        finally:
            self._cleanup()

class PtyClient(object):
    def __init__(self, cmd=""):
        self.cmd = cmd
        pass

    def connect(self, dst, port):
        try:
            self.sock = socket.socket(socket.AF_INET6 if ':' in dst else socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((dst, port))
        except socket.error, e:
            print "Error: %s" % repr(e)
            exit(1)

    def _send(self, **kwargs):
        cmd_str = json.dumps(kwargs)
        hdr = struct.pack(">L", len(cmd_str))
        self.sock.send(hdr + cmd_str)

    def run(self, args):
        self.connect(args.ip, args.port)
        self._send(cmd=self.cmd)

class RunProgram(PtyClient):
    def __init__(self):
        pass

    def run(self, args):
        self.connect(args.ip, args.port)

        if isinstance(args.program, (str, unicode)):
            args.program = [args.program]

        self._send(cmd="run", program=args.program)

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
        self._send(cmd="send-key", key=key)
        #self.sock.send(key)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", dest="port", default=14412, help="Port, default=%(default)d")
    parser.add_argument("-i", "--ip", dest="ip", default="localhost")

    subparsers = parser.add_subparsers(dest="action", title="Action")

    server_parser=subparsers.add_parser('server', help="Server mode")
    server_parser.add_argument("program", metavar="PROGRAM [ARGUMENTS ...]", nargs=argparse.REMAINDER, default=None)
    server_parser.set_defaults(cls=PtyServer())

    sk_parser =subparsers.add_parser('send-keys', help="Send-keys mode")
    sk_parser.add_argument("-l", help="Disable key name lookup", dest="expand", action="store_const", const=False, default=True)
    sk_parser.add_argument("keys", metavar="keys [keys ...]", nargs=argparse.REMAINDER)
    sk_parser.set_defaults(cls=SendKeys())

    subparsers.add_parser('sigterm', help="Send program sigterm").set_defaults(cls=PtyClient(cmd="sigterm"))
    subparsers.add_parser('kill', help="Send program kill").set_defaults(cls=PtyClient(cmd="sigkill"))
    run_parser = subparsers.add_parser('run', help="Run a new program")
    run_parser.add_argument("program", metavar="PROGRAM [ARGUMENTS ...]", nargs=argparse.REMAINDER, default=None)

    run_parser.set_defaults(cls=RunProgram())

    args = parser.parse_args()
    obj = args.cls
    obj.run(args)

    sys.exit(0)
