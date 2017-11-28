/* the most interactive and responsive shell ever made! */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

char cmdbuf[2048] = {0};
int cmdlen = 0;
volatile sig_atomic_t closeme = 0;

const char *logpath, *ip;

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
		fprintf(lf,"[%s] bogosh (%d): %s\n",stamp,getpid(),buf);
		fclose(lf);
	}
}

void sighandle( int signum )
{
	(void)signum;
	closeme = 1;
}

void dumpcmd( void )
{
	wlog("%s typed: %s",ip,cmdbuf);
	memset(cmdbuf,0,2048);
}

int main( int argc, char **argv )
{
	if ( argc < 3 )
		return 1;
	struct sigaction action;
	memset(&action,0,sizeof(struct sigaction));
	action.sa_handler = sighandle;
	sigaction(SIGTERM,&action,0);
	sigaction(SIGQUIT,&action,0);
	sigaction(SIGINT,&action,0);
	logpath = argv[1];
	ip = argv[2];
	wlog("launched for %s",ip);
	printf("# ");
	while ( !feof(stdin) && !closeme )
	{
		int ch = fgetc(stdin);
		if ( ch == '\n' )
		{
			if ( cmdlen ) printf("command not found\n");
			dumpcmd();
			printf("# ");
		}
		else if ( cmdlen < 2048 )
		{
			cmdbuf[cmdlen] = ch;
			cmdlen++;
		}
	}
	if ( cmdlen ) dumpcmd();
	wlog("terminated for %s",ip);
	return 0;
}
