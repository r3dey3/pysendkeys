pysendkeys is my answer to the problem of how get the functionality of tmux/screen send-keys without using tmux and screen.
I run a tiling window manager so I don't need the tiling of tmux/screen but I often want the functionality of being able
to run an app or send keys from a different session or a script.


## Usage
Start a server with `pysendkeys.py server [PROGRAM ARGS]`; the program and program arguments
are optional.

Send keys with `pysendkeys.py send-keys KEYS`. Escape sequences are handled.

Run a new program with `pysendkeys.py run PROGRAM [ARGS...]`; if the server was run with
a program argument it will just restart the program specified by the server; otherwise it will
kill the current running program (SIGTERM) and start the one specified in the command


### Using with pwntools
In order to use with pwntools, the pwntools-terminal script needs to be placed in your path.
It utilized the run functionality to run commands in the server window.

## Python interface
Python 2 is only supported right now; and there's no tests yet. But pysendkeys provides 3 classes:
* PtyServer - the server implementation
* PtyClient - client implementation; probably the more useful class
* FakePtyCleint - a null class that subclasses PtyClient but doesn't connect and just eats the keys

### PtyClient 
The main methods of PtyClient are:
* send_keys - send an array of keys, with optional meta key expansion
* send_key - send a single key
* kill - send a sigkill
* signal - send any signal
* run - Send a "run" command to run a new program

## Security
pysendkeys uses a TCP socket for communication, there is no authentication nor encryption on
this socket, so anybody that can connect to it can send keys and/or run arbitrary programs.
By default the socket only listens on localhost, so for single user systems this is mostly safe.

## Future features
* unix sockets/named sessions
