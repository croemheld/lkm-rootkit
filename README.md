# rootkit-kernel-module
A linux kernel module for hooking and exploiting kernel functions and user data.

### Rootkit functionalities:
- Covert communication channel
- System call table hook
- File hiding
- Kernel module hiding
- Network keylogging
- IPv4/IPv6 packet hiding
- Port knocking
- Privilege escalation
- Socket hiding

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
Note: the module has to be visible (i. e. not hidden) when unloading.

### Network keylogging
This functionality requires a syslog-ng server on the users machine. The destination port for receiving keylogger data is `514`, which can also be changed in the `include.h` on line 29 (`SYS_PORT`).

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
### Port knocking
### Privilege escalation
### Socket hiding
