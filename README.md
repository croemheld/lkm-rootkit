# rootkit-kernel-module
A linux kernel module for hooking and exploiting kernel functions and user data.

### Rootkit functionalities:
- [Covert communication channel](#covert-communication-channel)
- [System call table hook](#system-call-table-hook)
- [File hiding](#file-hiding)
- [Kernel module hiding](#kernel-module-hiding)
- [Network keylogging](#network-keylogging)
- [IPv4/IPv6 packet hiding](#ipv4ipv6-packet-hiding)
- [Port knocking](#port-knocking)
- [Privilege escalation](#privilege-escalation)
- [Socket hiding](#socket-hiding)

## Kernel module build and install
### Build
To compile this module, just run the Makefile with the `make` command in your terminal (requires root privileges). The generated `mod_rootkit.ko` kernel module is added to your folder.
### Install
Kernel modules are installed using the `insmod` command. In this project we also install two other modules (`nf_reject_ipv4` and `nf_reject_ipv6`) which are neccessary to enable and use all functionalities this rootkit offers. To install all modules at once, just use the `make load` command.

Now the rootkit module has been installed. The fun starts now!

## Rootkit functionalities
### Covert communication channel
When loading the rootkit, so is an UDP server inside this module. This UDP server acts as a server and a client together (more information later). To send commands to this kernel module, run the `nc` command on your machine. The port is always `8071`, which can be changed in the `include.h` file on line 28 (`UDP_PORT`). An example would look like this:
```
$ nc -4 -u localhost 8071
```
To send a command to this rootkit module, enter a valid command from the list of functionalities below and press Enter.

### System call table hook
The system call table is located at the beginning, reading from the `MSR_LSTAR` register. The address then is stored in an extern pointer which every file can access, if the files includes the `include.h` file. This address is then used to alter specific system call entries, like the `getdents`/`getdents64` function for file hiding.

### File hiding
This functionality allows the user to fide files starting with the `rootkit_` and `.rootkit_` prefix. To enable file hiding from your machine, use the covert channel and send the command
```
hidefile
```
To show the files again, send
```
showfile
```
In the future, variable prefixes are supported.

### Kernel module hiding
All kernel modules are being listed when typing `lsmod`. To prevent this module from being detected, send
```
hidemod
```
to your rootkit via UDP. To show the module again, send
```
showmod
```
> Note: The module has to be visible (i. e. not hidden) when unloading.

### Network keylogging
> Note: This functionality requires a syslog-ng server on the users machine. The destination port for receiving keylogger data is `514`, which can also be changed in the `include.h` on line 29 (`SYS_PORT`).

When enabling the keylogger with
```
keylog
```
This command hooks the `/dev/ttyS0` read function on the victims machine, storing all data typed in a terminal. The rootkit module allocates a buffer for every terminal (i. e. multiple PIDs when multiple terminals) and sends them to the user (you).
The data is then stored in your log file (path of the file depends on how you configure your syslog-ng server on your machine).
To disable the keylogger, send
```
keyunlog
```
Currently the receiver of the log messages is the user sending the `keylog` command. In the future the user can choose a remote server where the data is stored.

### IPv4/IPv6 packet hiding
The rootkit also offers a function to hide packets from specific senders. That is, an IPv4 or an IPv6 address passed via UDP command `hidepacket`. This time, we need to specify a transportation protocol and a senders IP address as a param, for example:
```
hidepacket-udp4-192.168.2.141
```
or for IPv6 addresses, either the full or shortened way:
```
hidepacket-udp6-0123:4567:89ab:cdef:0123:4567:89ab:cdef
hidepacket-tcp6-::1
```
The rootkit automatically detects the IP version, so there's no need for more information. The supported transportation protocols are: `udp4`, `udp6`, `tcp4` and `tcp6`. To test this functionality, start a packet analyzer on your victims machine (for example: WireShark) and look for the senders IP address. If you send a `hidepacket` command to your rootkit, WireShark should not be listing any packets from or to your specific IP address anymore.
To undo this, send a
```
showpacket-udp6-0123:4567:89ab:cdef:0123:4567:89ab:cdef
showpacket-tcp6-::1
```
command to your rootkit. The IP address should be the same address you sent to the kernel module when hiding all packets from and to this specific address.

### Port knocking
[Port knocking](https://en.wikipedia.org/wiki/Port_knocking) allows the user to hide specific ports on the victims machine, only accesable to whom "knocks" on a specific order of different ports. First of all, you send a message to your rootkit declaring the port you want to hide:
```
hideport-12345
```
When trying to send a message via `nc` to this specific port on your victims machine, the port is not accessible. You have to knock on other ports first to gain access to your hidden port. As for now, the "knocking ports" are always `2345`, `3456` and `4567`. Those ports can be changed in the `port_knocking.c` file on line 14 (`knocking_ports`). 
If you want to change the amount of ports to knock you have to alter the array size defined in `port_knocking.h` on line 15 (`KNOCKING_LENGTH`).
To make the hidden port visible again, send the command:
```
showport-12345
```

### Privilege escalation
> Note: This functionality is still buggy. Please be careful with your machine when escalating a process.
Escalating a process privileges to root and also make this process adopted by the init process. To escalate a process to root, send the command `escalate` along with the PID of the process to your rootkit:
```
escalate-12345
```
After this all child processes born from this process also have root privileges. If the specific process already has children, the privileges of the children don't change. 
The specific process is now adopted by the init process. The children of this process are unaffected by this action.
To deescalate a process to its original privileges, send
```
deescalate-12345
```
> Note: You can only deescalate processes you have escalated before.

### Socket hiding
To hide a socket you need to specify a transportation protocol and a port (similar to the [packet hiding](#ipv4ipv6-packet-hiding) functionality). The supported protocols are the same (`udp4`, `udp6`, `tcp4`, `tcp6`). For example:
```
hidesocket-udp4-12345
hidesocket-udp6-12346
hidesocket-tcp4-12347
hidesocket-tcp6-12348
```
The socket is now hidden, but still accessible. This way you can hide the communication channel between your host and the victims machine. The victim cannot detect the socket you use to send commands to your rootkit module.
To make a socket visible again, send
```
showsocket-udp4-12345
showsocket-udp6-12346
showsocket-tcp4-12347
showsocket-tcp6-12348
```
