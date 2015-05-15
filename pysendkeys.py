#!/usr/bin/env python


import array
import fcntl
import os
import pty
import select
import signal
import sys
import termios
import tty

import socket

def set_pty_size():
	buf = array.array('h', [0, 0, 0, 0])
	fcntl.ioctl(pty.STDOUT_FILENO, termios.TIOCGWINSZ, buf, True)
	#fcntl.ioctl(master_fd, termios.TIOCSWINSZ, buf)
	#print "%r" % buf


def signal_winch(signum, frame):
	'''
	Signal handler for SIGWINCH - window size has changed.
	'''
	set_pty_size()



def log(s):
    with open("/tmp/log", "a") as f:
        f.write("%s\n" % s)


def os_write_all(fd, data):
	assert fd is not None
	while data != '':
		n = os.write(fd, data)
		data = data[n:]



s = socket.socket()

host = socket.gethostname()
s.bind(('::',port))
s.listen(50)
s.setblocking(0)


child_pid, master_fd = pty.fork()
#print "%r, %r" % (child_pid, master_fd)
if child_pid == pty.CHILD:
	del sys.argv[0]
	#print "running %r" % (sys.argv)
	os.execlp(sys.argv[0], *sys.argv)
	sys.exit(0)

old_handler = signal.signal(signal.SIGWINCH, signal_winch)
try:
	mode = tty.tcgetattr(pty.STDIN_FILENO)
	tty.setraw(pty.STDIN_FILENO)
	restore = 1
except tty.error:    # This is the same as termios.error
	restore = 0

set_pty_size()
try:
	p = select.epoll()
	p.register(master_fd, select.EPOLLIN)
	p.register(pty.STDIN_FILENO, select.EPOLLIN)
	
	m = {
		master_fd: pty.STDOUT_FILENO,
		pty.STDIN_FILENO: master_fd,
	}
	done = False
	while not done:
		events = p.poll()
		log("Events %r" % events)
		for fd, event in events:
			if event == select.EPOLLHUP:
				done = True
			data = os.read(fd, 4096)
			if fd == master_fd:
				log("FROM CHILD-> %r"  % data)
			else:
				log("TO CHILD-> %r"  % data)
			os_write_all(m[fd], data)
				#sys.stderr.write("fd = %r send=%r data =%r\r\n" % (fd, m[fd], data))

except (IOError, OSError):
	pass
finally:
	if restore:
		tty.tcsetattr(pty.STDIN_FILENO, tty.TCSAFLUSH, mode)
os.close(master_fd)
signal.signal(signal.SIGWINCH, old_handler)

#import code
#code.interact(local=locals())
