#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>

int
despatcher(u_int16_t bindport)
{
	int  serversock, mailacc;
	char buf[8192], cmdline[8192], attstr[8192];
	int retval;
	struct stat sb;
	struct sockaddr_in mserver, clientaddr;
	socklen_t l;
	pid_t pid;
	char *p;
	int  cnt, ret;
	char *sep, sub[1024], from[1024], to[1024], mailf[1024], att[1024];
	int attach = 0;

	serversock = socket(PF_INET, SOCK_STREAM, 0);
	if(serversock == -1) {
		perror("socket");
	}
	mserver.sin_addr.s_addr = inet_addr("127.0.0.1");
	mserver.sin_family = AF_INET;
	mserver.sin_port = htons(bindport);
	l = sizeof(mserver);

	retval = bind(serversock, (struct sockaddr *)&mserver, l);
	if(retval == -1) {
		perror("bind(2) on TCP socket...");
		syslog(LOG_ERR, "Could not bind port %d ...exiting",
		    bindport);
		exit(128);
	}
	listen(serversock, 1024);

	for(;;) {
		syslog(LOG_INFO, "Listening for Mail despatch requests");
		signal(SIGCHLD, SIG_IGN);
		mailacc  = accept(serversock, 
				(struct sockaddr *)&clientaddr, &l);
		if(mailacc == -1) {
			syslog(LOG_ERR, "TCP accept failed");
			perror("accept");
		}
		pid = fork();
		if(pid == -1) {
			perror("fork()");
			syslog(LOG_ERR, "Fork() failed, very bad");
		}    
		if(pid != 0) { /* Parent process */
			close(mailacc);
			continue;
		} else { 
			read(mailacc, buf, BUFSIZ);
			cnt = 0, attach = 0;
			p = buf;
			while( (sep = strsep(&p, "\n")) ) {
				switch(cnt) {
					case 0:
						strncpy(sub, sep, sizeof(sub));
						break;
					case 1:
						strncpy(from, sep, sizeof(from));
						break;
					case 2:
						strncpy(to, sep, sizeof(to));
						break;
					case 3:
						memset(mailf, 0, sizeof(mailf));
						strncpy(mailf, sep, 
						    sizeof(mailf));
						break;
					case 4:
						attach = 1;
						strncpy(att, sep, 
						    sizeof(att));
						break;
					default:
						break;
				
				}
				cnt++;
			}
			stat(mailf, &sb);
			syslog(LOG_INFO, "Mailing text of size %d", (int)sb.st_size);
			p = att;
			bzero(attstr, sizeof(attstr));
			if(p && attach) {
				while( (sep = strsep(&p, " ")) ) {
					if(*sep == '/') {
						strncat(attstr, " -a ", sizeof(attstr));
						strncat(attstr, sep, sizeof(attstr));	
					}
				}
			}
			memset(cmdline, 0, sizeof(cmdline));
			if(!strncmp(from, "STD", sizeof(from))) {
				snprintf(cmdline, sizeof(cmdline),
			             "/usr/local/bin/mutt -s \"%s\" %s -- %s < %s", 
				     sub, attstr, to, mailf);
			} else if(!strncmp(from, "SENDMAIL_RAW", sizeof(from))) {
				snprintf(cmdline, sizeof(cmdline),
				    "/usr/sbin/sendmail -t < %s", mailf);
			} else {
				snprintf(cmdline, sizeof(cmdline),
			    	    "export EMAIL=\"%s\";/usr/local/bin/mutt " 
				    "-s \"%s\" %s -- \"%s\" < %s", 
			    	   from, sub, attstr, to, mailf);
			}
			syslog(LOG_INFO, "I get cmdline as [%s]", cmdline);
			ret = system(cmdline);
			syslog(LOG_INFO, "system() returns %d", ret);
			exit(0);
		} 
	} /* for(;;) */
}

static void 
waitforkidandkill(int sig)
{
	int save_errno = errno;
	int status;
	pid_t pid;

	while((pid = waitpid(WAIT_ANY, &status, WNOHANG)) > 0 ||
			(pid < 0 && errno == EINTR))
		;
	signal(SIGCHLD, waitforkidandkill);
	errno = save_errno;

}


int
main(int argc, char **argv)
{
	u_int16_t bindport;
	pid_t pid;

	if(argc == 1) {
		printf("Please give the port to bind to\n");
		exit(128);
	}
	openlog("scmailer",  LOG_PID , LOG_LOCAL0);
	syslog(LOG_INFO, "Starting SMTP dispatcher process...");
	signal(SIGCHLD, waitforkidandkill);
	signal(SIGPIPE, SIG_IGN);

	bindport = strtol(argv[1], NULL, 10);

	daemon(0, 0);
	pid = fork();
	if(pid != 0) { /* Parent */
		;
	} else {/* Child */
		despatcher(bindport);
	}
	return 0;
}
