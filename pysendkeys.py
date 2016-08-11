#!/usr/bin/env python2
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
import logging

LOG = True

__all__ = [
    "PtyServer",
    "PtyClient"
]

PORT = 14412


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
        #  self.srv_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self.srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv_sock.setblocking(0)
        self.srv_sock.bind((ip, port))
        self.srv_sock.listen(5)
        self.ep.register(self.srv_sock.fileno(), select.EPOLLIN)
        self.clients = {}
        self.client_bufs = {}

    def _handle_sigwinch(self, signum, frame):
        self._set_pty_size()

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

    def _set_pty_size(self):
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

    def stop_process(self, sig=signal.SIGTERM):
        self.kill_process()
        self._close_master()

    def kill_process(self, sig=signal.SIGTERM):
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
            logging.debug(key)
            if self.master_fd is not None:
                for v in key:
                    os_write_all(self.master_fd, v)
        elif cmd == u"run":
            program = kwargs["program"]
            self.start_process(program)
        elif cmd == u"sigterm":
            self.kill_process(signal.SIGTERM)
        elif cmd == u"sigkill":
            self.kill_process(signal.SIGKILL)
        elif cmd == u"sigint":
            self.kill_process(signal.SIGINT)
        elif cmd == u"signal":
            self.kill_process(int(kwargs["signum"]))

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
                logging.debug("Exception in handle_client %r" % e)

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

    def __call__(self, args):
        self.program = args.program
        # or ["/bin/cat"]
        self.master_fd = None

        try:
            self._setup()
            self._open_server(args.ip, args.port)
            self.start_process(self.program)

            done = False
            while not done:
                try:
                    events = self.ep.poll()
                except IOError:
                    continue
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
            logging.debug("Exception in main %r" % e)
            raise
        finally:
            self._cleanup()


class PtyClient(object):
    def __init__(self, cmd=""):
        self.cmd = cmd
        pass

    def connect(self, dst, port=PORT):
        try:
            sock_type = socket.AF_INET6 if ':' in dst else socket.AF_INET
            self.sock = socket.socket(sock_type, socket.SOCK_STREAM)
            self.sock.connect((dst, port))
        except socket.error as e:
            print("Error: %s" % repr(e))
            exit(1)

    def _send(self, **kwargs):
        cmd_str = json.dumps(kwargs)
        hdr = struct.pack(">L", len(cmd_str))
        self.sock.send(hdr + cmd_str)

    def __call__(self, args):
        self.connect(args.ip, args.port)
        self._send(cmd=self.cmd)

    def run(self, program=[]):
        if isinstance(program, (str, unicode)):
            program = [program]

        self._send(cmd="run", program=program)

    def send_key(self, key, expand=True):
        if expand:
            key_up = key.upper()
            meta = ""
            if key_up.startswith("M-"):
                meta = "\x1b"
                key = key[2:]
            mapping = {
                "BSPACE": "\x08",
                "BS": "\x08",
                "DEL": "\x1b[3~", "C-DEL": "\x1b[3^",
                "BTAB": "",
                "DC": "",  # Delete Char
                "IC": "",  # Insert Char
                "SPACE": " ",
                "C-SPACE": "\x00",
                "TAB": "\t",
                "S-TAB": "\x1b[Z",
                "ENTER": "\n",
                "UP": "\x1b[A",
                "DOWN": "\x1b[B",
                "RIGHT": "\x1b[C",
                "LEFT": "\x1b[D",
                "C-UP": "\x1bOa",
                "C-DOWN": "\x1bOb",
                "C-RIGHT": "\x1bOc",
                "C-LEFT": "\x1bOd",
                "F1": "\x1b[11^", "F2": "\x1b[12^",
                "F3": "\x1b[13^", "F4": "\x1b[14^",
                "F5": "\x1b[15^", "F6": "\x1b[17^",
                "F7": "\x1b[18^", "F8": "\x1b[19^",
                "F9": "\x1b[20^", "F10": "\x1b[21^",
                "F11": "\x1b[23^", "F12": "\x1b[24^",
                "C-F1": "\x1b[11^", "C-F2": "\x1b[12^",
                "C-F3": "\x1b[13^", "C-F4": "\x1b[14^",
                "C-F5": "\x1b[15^", "C-F6": "\x1b[17^",
                "C-F7": "\x1b[18^", "C-F8": "\x1b[19^",
                "C-F9": "\x1b[20^", "C-F10": "\x1b[21^",
                "C-F11": "\x1b[23^", "C-F12": "\x1b[24^",
                "ESCAPE": "\x1b",
                "HOME": "\x1b[1~", "C-HOME": "\x1b[1^",
                "END": "\x1b[4~", "C-END": "\x1b[4^",
                "PGUP": "\x1b[5~", "C-PGUP": "\x1b[5^",
                "PGDN": "\x1b[6~", "C-PGDN": "\x1b[6^",
            }
            try:
                key = mapping[key_up]
            except:
                if key_up.startswith("C-") and len(key) == 3:
                    k = key_up[2]
                    if k in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                        key = chr(ord(k) - ord('A') + 1)
                elif key.startswith("^") and len(key) == 2:
                    k = key_up[1]
                    if k in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                        key = chr(ord(k) - ord('A') + 1)

            key = meta + key

        self._send(cmd="send-key", key=key)

    def send_keys(self, keys, expand=True):
        for k in keys:
            self.send_key(k, expand)

    def kill(self):
        self._send(cmd='sigkill')

    def sigterm(self):
        self._send(cmd='sigterm')

    def sigint(self):
        self._send(cmd='sigint')

    def signal(self, signum):
        self._send(cmd='signal', signum=signum)


class RunProgram(PtyClient):
    def __call__(self, args):
        self.connect(args.ip, args.port)
        self.run(args.program)


class SendKeys(PtyClient):
    def __call__(self, args):
        self.connect(args.ip, args.port)
        self.send_keys(args.keys, args.expand)


class SendFile(PtyClient):
    def __call__(self, args):
        self.connect(args.ip, args.port)
        data = args.file.read()
        self.send_keys(data, False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", dest="port", default=PORT, type=int, help="Port, default=%(default)d")
    parser.add_argument("-i", "--ip", dest="ip", default="localhost")

    subparsers = parser.add_subparsers(dest="action", title="Action")
    subparsers.required = True

    server_parser = subparsers.add_parser('server', help="Server mode")
    server_parser.add_argument("program", metavar="PROGRAM [ARGUMENTS ...]", nargs=argparse.REMAINDER, default=None)
    server_parser.set_defaults(cls=PtyServer())

    sk_parser = subparsers.add_parser('send-keys', help="Send-keys mode")
    sk_parser.add_argument("-l", help="Disable key name lookup", dest="expand", action="store_const", const=False, default=True)
    sk_parser.add_argument("keys", metavar="keys [keys ...]", nargs=argparse.REMAINDER)
    sk_parser.set_defaults(cls=SendKeys())

    sf_parser = subparsers.add_parser('send-file', help="Send-file mode")
    sf_parser.add_argument("file", metavar="FILENAME", type=file)
    sf_parser.set_defaults(cls=SendFile())

    subparsers.add_parser('sigterm', help="Send program sigterm").set_defaults(cls=PtyClient(cmd="sigterm"))
    subparsers.add_parser('kill', help="Send program kill").set_defaults(cls=PtyClient(cmd="sigkill"))
    run_parser = subparsers.add_parser('run', help="Run a new program")
    run_parser.add_argument("program", metavar="PROGRAM [ARGUMENTS ...]", nargs=argparse.REMAINDER, default=None)
    run_parser.set_defaults(cls=RunProgram())

    args = parser.parse_args()
    obj = args.cls
    obj(args)

    sys.exit(0)
