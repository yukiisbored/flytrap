Flytrap is a tiny SSH honeypot that blindly accepts all login attempts and
drops connections into a fake shell that does nothing. All communication will
be logged.

By default it expects to be installed in /opt/flytrap. Don't forget to
generate a RSA host key (default filename is "hostkey.rsa").

Flytrap will switch to the "nobody" user (by default) when run as root, y'know
for safety. Still, just in case, make sure to keep backups.

Requirements:
 * libssh
 * an easily accessible host
 * some unfortunate victims
