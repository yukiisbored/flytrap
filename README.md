Flytrap is a tiny SSH honeypot that blindly accepts all login attempts and
drops connections into a fake shell that does nothing. All communication will
be logged.

It's recommended to make a separate user for the Flytrap server for it to drop
privileges to after binding to port 22 (or any other port chosen in the build
config). By default everything is logged to /var/log/flytrap.log (will be
created if it doesn't exist).

Requirements:
 * libssh
 * an easily accessible host
 * some unfortunate victims
