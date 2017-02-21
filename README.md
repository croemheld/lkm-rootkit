# rootkit-kernel-module
A linux kernel module for hooking and exploiting kernel functions and user data.

### Rootkit functionalities:
- System call table hook
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
