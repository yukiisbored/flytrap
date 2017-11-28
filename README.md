Flytrap is a tiny SSH honeypot that blindly accepts all login attempts and
drops connections into a fake shell that does nothing. All communication will
be logged.

It's recommended to make a separate user for the Flytrap server for it to drop
privileges to after binding to port 22 (or any other port chosen in the build
config). By default it expects to be installed in /opt/flytrap. Don't forget to
generate a RSA host key (default filename is "hostkey.rsa").

Requirements:
 * libssh
 * an easily accessible host
 * some unfortunate victims
