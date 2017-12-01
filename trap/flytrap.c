/*
	flytrap.c : The SSH server proper, does most of the heavy lifting.
	Part of Flytrap, a small SSH honeypot.
	(C)2017 Marisa Kirisame, UnSX Team.
	Released under the GNU General Public License version 3 (or later).
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <poll.h>
#include <pty.h>
#include <sys/wait.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include "config.h"

int bindport = FT_DEFPORT;
char *bindaddr = FT_DEFADDR;
char *setuser = FT_DEFUSER;
char *logpath = FT_DEFLOG;
char *keypath = FT_DEFKEY;
char *bogoshpath = FT_DEFBGSH;
int nodaemon = 0;

void wlog( const char *fmt, ... )
{
	va_list arg;
	char stamp[256], buf[1024];
	time_t tt = time(0);
	strftime(stamp,256,"%Y-%m-%d %H:%M:%S",localtime(&tt));
	va_start(arg,fmt);
	vsnprintf(buf,1024,fmt,arg);
	va_end(arg);
	FILE *lf;
	if ( (lf = fopen(logpath,"a+")) != 0 )
	{
		fprintf(lf,"[%s] flytrap (%d): %s\n",stamp,getpid(),buf);
		fclose(lf);
	}
}

int switch_user( void )
{
	struct passwd *pw;
	struct group *gr;
	pw = getpwnam(setuser);
	if ( !pw )
	{
		wlog("username %s does not exist!",setuser);
		return 1;
	}
	gr = getgrgid(pw->pw_gid);
	if ( !gr )
	{
		wlog("cannot get info for gid %d: %s",pw->pw_gid,
			strerror(errno));
		return 1;
	}
	if ( chown(logpath,pw->pw_uid,pw->pw_gid) == -1 )
	{
		wlog("cannot set permissions for %s: %s",logpath,
			strerror(errno));
		return 1;
	}
	if ( setgid(pw->pw_gid) == -1 )
	{
		wlog("cannot set group %s: %s",gr->gr_name,strerror(errno));
		return 1;
	}
	if ( setuid(pw->pw_uid) == -1 )
	{
		wlog("cannot set user %s: %s",setuser,strerror(errno));
		return 1;
	}
	wlog("successfully switched to %s:%s",setuser,gr->gr_name);
	return 0;
}

int sh_copyfrom( socket_t fd, int rev, void *userdata )
{
	ssh_channel chn = (ssh_channel)userdata;
	char buf[2048];
	int sz = 0;
	if ( !chn )
	{
		close(fd);
		return -1;
	}
	if ( rev & POLLIN )
	{
		sz = read(fd,buf,2048);
		if ( sz > 0 ) ssh_channel_write(chn,buf,sz);
	}
	if ( rev & POLLHUP )
	{
		ssh_channel_close(chn);
		sz = -1;
	}
	return sz;
}

int sh_copyto( ssh_session s, ssh_channel chn, void *data, uint32_t len,
	int is_stderr, void *userdata )
{
	int fd = *(int*)userdata;
	(void)s, (void)chn, (void)is_stderr;
	int sz = write(fd,data,len);
	return sz;
}

void sh_close( ssh_session s, ssh_channel chn, void *userdata )
{
	int fd = *(int*)userdata;
	(void)s, (void)chn;
	close(fd);
}

struct ssh_channel_callbacks_struct shcb =
{
	.channel_data_function = sh_copyto,
	.channel_eof_function = sh_close,
	.channel_close_function = sh_close,
	.userdata = 0
};

int trap_fly( ssh_session s )
{
	int retcode = 0;
	ssh_message m;
	char ip[INET6_ADDRSTRLEN];
	/* look at all this boilerplate just to get an IP */
	struct sockaddr_storage st;
	struct sockaddr_in *in;
	socklen_t stlen = sizeof(st);
	getpeername(ssh_get_fd(s),(struct sockaddr *)&st,&stlen);
	in = (struct sockaddr_in *)&st;
	inet_ntop(AF_INET,&in->sin_addr,ip,sizeof(ip));
	/* holy maccaroni */
	if ( ssh_handle_key_exchange(s) )
	{
		wlog("%s key exchange error: %s",ip,ssh_get_error(s));
		ssh_disconnect(s);
		return 1;
	}
	int auth = 0;
	do
	{
		m = ssh_message_get(s);
		if ( !m ) break;
		switch ( ssh_message_type(m) )
		{
		case SSH_REQUEST_AUTH:
			switch( ssh_message_subtype(m) )
			{
			case SSH_AUTH_METHOD_PASSWORD:
				wlog("%s login as %s with password %s",
					ip,ssh_message_auth_user(m),
					ssh_message_auth_password(m));
				auth = 1;
				ssh_message_auth_reply_success(m,0);
				break;
			case SSH_AUTH_METHOD_NONE:
			default:
				ssh_message_auth_set_methods(m,
					SSH_AUTH_METHOD_PASSWORD);
				ssh_message_reply_default(m);
				break;
			}
			break;
		default:
			ssh_message_reply_default(m);
			break;
		}
		ssh_message_free(m);
	} while ( !auth );
	if ( !auth )
	{
		wlog("%s auth error: %s",ip,ssh_get_error(s));
		ssh_disconnect(s);
		return 1;
	}
	ssh_channel chn = 0;
	do
	{
		m = ssh_message_get(s);
		if ( !m ) break;
		if ( (ssh_message_type(m) == SSH_REQUEST_CHANNEL_OPEN)
			&& (ssh_message_subtype(m) == SSH_CHANNEL_SESSION) )
			chn = ssh_message_channel_request_open_reply_accept(m);
		else ssh_message_reply_default(m);
		ssh_message_free(m);
	} while ( !chn );
	if ( !chn )
	{
		wlog("%s channel open error: %s",ip,ssh_get_error(s));
		ssh_disconnect(s);
		return 1;
	}
	int shl = 0, exc = 0;
	char cmd[1024];
	do
	{
		m = ssh_message_get(s);
		if ( !m ) break;
		if ( ssh_message_type(m) != SSH_REQUEST_CHANNEL )
		{
			ssh_message_reply_default(m);
			ssh_message_free(m);
			continue;
		}
		if ( ssh_message_subtype(m) == SSH_CHANNEL_REQUEST_EXEC )
		{
			exc = 1;
			strncpy(cmd,ssh_message_channel_request_command(m),
				1024);
			ssh_message_channel_request_reply_success(m);
			ssh_message_free(m);
			break;
		}
		else if ( ssh_message_subtype(m) == SSH_CHANNEL_REQUEST_SHELL )
		{
			shl = 1;
			ssh_message_channel_request_reply_success(m);
			ssh_message_free(m);
			break;
		}
		else if ( ssh_message_subtype(m) == SSH_CHANNEL_REQUEST_PTY )
		{
			ssh_message_channel_request_reply_success(m);
			ssh_message_free(m);
			continue;
		}
	} while ( !shl && !exc );
	if ( !shl && !exc )
	{
		wlog("%s shell/exec request error: %s",ip,ssh_get_error(s));
		retcode = 1;
		goto bail_out;
	}
	wlog("%s took the bait successfully",ip);
	if ( exc )
	{
		wlog("%s requested to execute a command: %s",ip,cmd);
	}
	else if ( shl )
	{
		wlog("%s requested to open a shell",ip);
		socket_t fd;
		struct termios *term = 0;
		struct winsize *wsz = 0;
		pid_t shpd;
		ssh_event ev;
		short evmask = POLLIN|POLLPRI|POLLERR|POLLHUP|POLLNVAL;
		shpd = forkpty(&fd,0,term,wsz);
		if ( shpd == 0 )
		{
			execl(bogoshpath,bogoshpath,logpath,ip,0);
			abort();
		}
		shcb.userdata = &fd;
		ssh_callbacks_init(&shcb);
		ssh_set_channel_callbacks(chn,&shcb);
		ev = ssh_event_new();
		if ( !ev )
		{
			wlog("couldn't get event");
			retcode = 1;
			goto bail_out;
		}
		if ( ssh_event_add_fd(ev,fd,evmask,sh_copyfrom,chn) != SSH_OK )
		{
			wlog("couldn't add fd to event");
			retcode = 1;
			goto bail_out;
		}
		if ( ssh_event_add_session(ev,s) != SSH_OK )
		{
			wlog("couldn't add session to event");
			retcode = 1;
			goto bail_out;
		}
		do
		{
			ssh_event_dopoll(ev,1000);
		} while ( !ssh_channel_is_closed(chn)
			&& !waitpid(shpd,0,WNOHANG) );
		ssh_event_remove_fd(ev,fd);
		ssh_event_remove_session(ev,s);
		ssh_event_free(ev);
	}
bail_out:
	if ( !ssh_channel_is_closed(chn) ) ssh_channel_close(chn);
	ssh_channel_free(chn);
	ssh_disconnect(s);
	return retcode;
}

int main( int argc, char **argv )
{
	int opt, npid;
	ssh_bind s_bind;
	ssh_session s_session;
	while ( (opt = getopt(argc,argv,"hfp:a:l:k:u:b:")) != -1 )
	{
		switch ( opt )
		{
		case 'p':
			sscanf(optarg,"%d",&bindport);
			break;
		case 'a':
			bindaddr = optarg;
			break;
		case 'l':
			logpath = optarg;
			break;
		case 'k':
			keypath = optarg;
			break;
		case 'u':
			setuser = optarg;
			break;
		case 'b':
			bogoshpath = optarg;
			break;
		case 'f':
			nodaemon = 1;
			break;
		case 'h':
		default:
			fprintf(stderr,"usage: %s [-h] [-f] [-p port]"
				" [-a address] [-l logpath] [-k keypath]"
				" [-u setuser]"
				" [-b path to bogosh executable]\n",argv[0]);
			exit(1);
		}
	}
	if ( nodaemon ) goto dont_daemon;
	int dpid = fork();
	if ( dpid < 0 )
	{
		fprintf(stderr,"failed to daemonize: %s\n",strerror(errno));
		exit(1);
	}
	else if ( dpid > 0 )
		exit(0);
dont_daemon:
	signal(SIGCHLD,SIG_IGN);
	wlog("started daemon for %s:%d",bindaddr,bindport);
	s_session = ssh_new();
	s_bind = ssh_bind_new();
	ssh_bind_options_set(s_bind,SSH_BIND_OPTIONS_BINDADDR,bindaddr);
	ssh_bind_options_set(s_bind,SSH_BIND_OPTIONS_BINDPORT,&bindport);
	ssh_bind_options_set(s_bind,SSH_BIND_OPTIONS_RSAKEY,keypath);
	if ( ssh_bind_listen(s_bind) < 0 )
	{
		wlog("ssh bind error: %s",ssh_get_error(s_bind));
		exit(1);
	}
	if ( setuser ) switch_user();
	for( ; ; )
	{
		if ( ssh_bind_accept(s_bind,s_session) == SSH_ERROR )
		{
			wlog("ssh accept error: %s",ssh_get_error(s_bind));
			continue;
		}
		npid = fork();
		if ( npid < 0 )
		{
			wlog("couldn't fork: %s",strerror(errno));
			continue;
		}
		if ( npid == 0 )
		{
			exit(trap_fly(s_session));
		}
	}
	exit(0);
}
