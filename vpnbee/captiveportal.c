#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <err.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <sys/queue.h>
#include <sys/poll.h>

#define PFCTL "/sbin/pfctl"
#define CONFIG "/etc/fw.conf"
#define SOCK_PATH "/tmp/captive"

#define DAY_SUNDAY 0x1
#define DAY_MONDAY 0x2
#define DAY_TUESDAY 0x4
#define DAY_WEDNESDAY 0x8
#define DAY_THURSDAY 0x10
#define DAY_FRIDAY 0x20
#define DAY_SATURDAY 0x40

#define REASON_TOTAL_BW_EXCEEDED 30
#define REASON_UPLOAD_BW_EXCEEDED 20
#define REASON_DOWNLOAD_BW_EXCEEDED 10
#define REASON_TIMER_EXPIRED 15

struct captivehosts {
	char label[1024];
	char host[1024];
	char user[1024];
	char mac[1024];
	char bw[1024];
	int duration;
	unsigned long totalcap;
	unsigned long uploadcap;
	unsigned long dlcap;
	int timealloc;
	int elapsed;
	SLIST_ENTRY(captivehosts) next;
} captivehosts;

static SLIST_HEAD(, captivehosts) captivehostshead;

struct timebasedrules {
	char label[1024];
	char host[1024];
	char dayweek;
	char starttime[1024];
	char endtime[1024];
	char fwflag[1024];
	SLIST_ENTRY(timebasedrules) next;
} timebasedrules;

static SLIST_HEAD(, timebasedrules) timebasedruleshead;

/* function declarations */

/* XXX captive */
void killhost(struct captivehosts *tmp, int reason);
int addhost(struct captivehosts *h);
int periodic_wakeup(void) ;
int remove_line(char*);
void check_bw_hosts(struct captivehosts *h);
int start_captive(void);

/* XXX timebased access */
void printdayweek(char dayweek,char *daystring);
void inserttimerule(struct timebasedrules *t);
void removetimerule(struct timebasedrules *t);
int checkdays(char dayweek);
int checktimeaccess(struct timebasedrules *t);

/* common */
void check_timer_hosts(int sig);
int start_timer(void);
int main(void);


/* common functions */
/* This is for the fork() zombie issue */
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

/* time based */
void printdayweek(char dayweek, char *daystring)
{
	memset(daystring, 0, sizeof(daystring));

	if(dayweek & DAY_SUNDAY) {
		strlcat(daystring, "Sun ", 1024);		
	}
	if(dayweek & DAY_MONDAY) {
		strlcat(daystring, "Mon ", 1024);		
	}
	if(dayweek & DAY_TUESDAY) {
		strlcat(daystring, "Tue ", 1024);		
	}
	if(dayweek & DAY_WEDNESDAY) {
		strlcat(daystring, "Wed ", 1024);		
	}
	if(dayweek & DAY_THURSDAY) {
		strlcat(daystring, "Thu ", 1024);		
	}
	if(dayweek & DAY_FRIDAY) {
		strlcat(daystring, "Fri ", 1024);		
	}
	if(dayweek & DAY_SATURDAY) {
		strlcat(daystring, "Sat ", 1024);		
	}
	return;
}

/* common functions */
int copyblock(char *parm, char *lines)
{	char *p, *sep, *copy, *p2, *sep2;
	struct captivehosts *tmp;
	struct timebasedrules *tmp2;
	char days[1024], daystring[1024];
	char dur[1024], upl[1024], dl[1024],tot[1024];
	int cnt;

	if(!strcmp(parm, "timebased_rules")) {
		while (!SLIST_EMPTY(&timebasedruleshead)) {           /* Delete. */
			tmp2 = SLIST_FIRST(&timebasedruleshead);
			SLIST_REMOVE_HEAD(&timebasedruleshead, next);
			free(tmp2);
		}

		p = strndup(lines, 16384);
		while( (sep = strsep(&p, "\n")) ) {
			if(strlen(sep) == 0)
				continue;
			tmp2 = malloc(sizeof(struct timebasedrules));
			sscanf(sep, "\t%s %s %s %s %s %s",  tmp2->label, tmp2->host, days, 
					tmp2->starttime, tmp2->endtime, tmp2->fwflag);

			copy = strdup(days);
			if(strncmp(copy, "ALL", strlen(copy)) == 0) {
				tmp2->dayweek |= DAY_SUNDAY;
				tmp2->dayweek |= DAY_MONDAY;
				tmp2->dayweek |= DAY_TUESDAY;
				tmp2->dayweek |= DAY_WEDNESDAY;
				tmp2->dayweek |= DAY_THURSDAY;
				tmp2->dayweek |= DAY_FRIDAY;
				tmp2->dayweek |= DAY_SATURDAY;
			}
			while( (p2 = strsep(&copy, ",")) ) {
				if(strncmp(p2, "Sun", strlen(p)) == 0) {
					tmp2->dayweek |= DAY_SUNDAY;
				} else if(strncmp(p2, "Mon", strlen(p)) == 0) {
					tmp2->dayweek |= DAY_MONDAY;
				} else if(strncmp(p2, "Tue",  strlen(p)) == 0) {
					tmp2->dayweek |= DAY_TUESDAY;
				} else if(strncmp(p2, "Wed",  strlen(p)) == 0) {
					tmp2->dayweek |= DAY_WEDNESDAY;
				} else if(strncmp(p2, "Thu",  strlen(p)) == 0) {
					tmp2->dayweek |= DAY_THURSDAY;
				} else if(strncmp(p2, "Fri",  strlen(p)) == 0) {
					tmp2->dayweek |= DAY_FRIDAY;
				} else if(strncmp(p2, "Sat",  strlen(p)) == 0) {
					tmp2->dayweek |= DAY_SATURDAY;
				} 
			}
			free(copy); 

			SLIST_INSERT_HEAD(&timebasedruleshead, tmp2, next);
		} 

		free(p);
		SLIST_FOREACH(tmp2, &timebasedruleshead, next) {
			printdayweek(tmp2->dayweek, daystring);
			syslog(LOG_INFO, " Time based rules %s %s %s %s %s %s", tmp2->label, tmp2->host, daystring, tmp2->starttime, tmp2->endtime,  tmp2->fwflag);
		}
	}
	if(!strcmp(parm, "captive_hosts")) {
		while (!SLIST_EMPTY(&captivehostshead)) {           /* Delete. */
			tmp = SLIST_FIRST(&captivehostshead);
			SLIST_REMOVE_HEAD(&captivehostshead, next);
			free(tmp);
		}

		p = strndup(lines, 16384);
		while( (sep = strsep(&p, "\n")) ) {
			if(strlen(sep) == 0)
				continue;
			tmp = malloc(sizeof(struct captivehosts));
			p2 = strndup(sep, 16384);
			cnt = 0;
			while( (sep2 = strsep(&p2, ",")) ) {
				if(strlen(sep2) == 0)
					continue;
				if(cnt == 0) {	
					strlcpy(tmp->user, sep2 + 1, 1024);
				} else if(cnt == 1) {
					strlcpy(tmp->label, sep2, 1024);
				} else if(cnt == 2) {
					strlcpy(tmp->host, sep2, 1024);
				} else if(cnt == 3) {
					strlcpy(tmp->mac, sep2, 1024);
				} else if(cnt == 4) {
					strlcpy(dur, sep2, 1024);
				} else if(cnt == 5) {
					strlcpy(tot, sep2, 1024);
				} else if(cnt == 6) {
					strlcpy(upl, sep2, 1024);
				} else if(cnt == 7) {
					strlcpy(dl, sep2, 1024);
				} else if(cnt == 8) {
					strlcpy(tmp->bw, sep2, 1024);
				}
				cnt++;
			}
			free(p2);

			tmp->duration = strtol(dur, NULL,10);
			tmp->totalcap = strtol(tot, NULL,10);
			tmp->uploadcap =strtol(upl, NULL,10);
			tmp->dlcap = strtol(dl, NULL,10);


			if(strstr(dur, "min")) {
				tmp->duration *= 60;
			} else if(strstr(dur, "hrs")) {
				tmp->duration *= 3600;
			}

			if(strstr(tot, "mb")) {
				tmp->totalcap *= 1024 * 1024;
			} else if(strstr(tot, "gb")) {
				tmp->totalcap *= 1024 * 1024 * 1024;
			}

			if(strstr(upl, "mb")) {
				tmp->uploadcap *= 1024 * 1024;
			} else if(strstr(upl, "gb")) {
				tmp->uploadcap *= 1024 * 1024 * 1024;
			}


			if(strstr(dl, "mb")) {
				tmp->dlcap *= 1024 * 1024;
			} else if(strstr(dl, "gb")) {
				tmp->dlcap *= 1024 * 1024 * 1024;
			}

			tmp->timealloc = tmp->duration;
			tmp->elapsed = 0;
			SLIST_INSERT_HEAD(&captivehostshead, tmp, next);
			addhost(tmp);

		} 
		free(p);
		SLIST_FOREACH(tmp, &captivehostshead, next) {
			syslog(LOG_INFO, " Captive hosts [%s] %s %s %d %ld %ld %ld %s", 
					tmp->label, tmp->user, tmp->host,
					tmp->duration, tmp->totalcap, tmp->uploadcap, tmp->dlcap, tmp->bw);
		}
	}
	return 0;
}

/* common functions */
/* Config file parsing of sc.conf */

int copyvals(char *parm, char *val)
{
	if(!strcmp(parm, "captive_use_dhcp")) {
		if(strstr(val, "yes")) {
			syslog(LOG_INFO, "DHCP server enabled in fw.conf");
		} else {
			syslog(LOG_INFO, "DHCP server disabled in fw.conf");
		}
	} else if(!strcmp(parm, "captive_enable")) {
		if(strstr(val, "yes")) {
			syslog(LOG_INFO, "Captive portal enabled in sc.conf");
		} else {
			syslog(LOG_INFO, "Captive portal disabled in sc.conf");
		}
	}
	return 0;
}

/* common functions */
	void
configparse(int sig)
{
	int cfd, b, sec = 0;
	char *p, *copy, *t, *sp;
	char  buf[16384], blockbuf[16384];
	char parm[1024], val[1024];

	cfd = open(CONFIG, O_RDONLY);
	if(cfd == -1) {
		perror("open");
		syslog(LOG_ERR, "Cannot open config file");
	}

	SLIST_INIT(&captivehostshead);
	SLIST_INIT(&timebasedruleshead);

	/* First read a big chunk of the file */
	memset(blockbuf, 0, sizeof(blockbuf));
	sec = 0;
	while( (b = read(cfd, buf, sizeof(buf))) ) {
		copy = strdup(buf);
		t = copy;
		/* Then read it line by line */
		while( (p = strsep(&copy, "\n")) ) {
			/* Skip comments and empty lines */
			if(*p == '#' || *p == 0)
				continue;
			if(strchr(p, '}')) {
				sec = 0;
				copyblock(parm, blockbuf);
				/* reset the lines buffer */
				blockbuf[0] = 0;
				continue;
			}
			if(sec) {
				strlcat(blockbuf, p, sizeof(blockbuf));
				strlcat(blockbuf, "\n", sizeof(blockbuf));
				continue;
			}
			if( (sp = strchr(p, '{')) ) {
				strlcpy(parm, p, sp - p);
				sec = 1;
				continue;
			}
			sp = strchr(p, ' ');
			if(sp) {
				strlcpy(parm , p, sp - p + 1); 
				strlcpy(val, sp + 1, sizeof(val));
				copyvals(parm, val);
			}
		}    
		free(t);
	}    
	close(cfd);
	signal(SIGHUP, configparse);
	return;
}

/* captive */
int addhost(struct captivehosts *h)
{
	char cmd[8192];
	syslog(LOG_INFO, "Adding host %s(%s) to PF table", h->host, h->label);
	snprintf(cmd, sizeof(cmd), "%s -t captivehosts -T add %s", PFCTL, h->host);
	system(cmd);
	if(!strncmp(h->bw, "512kbps", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t bw512kbps -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 512 kbps table", h->host, h->label);
	} else if(!strncmp(h->bw, "4096kbps", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw512KB -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 512 KB table", h->host, h->label);
	} else if(!strncmp(h->bw, "8Kb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw1meg -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 1MB table", h->host, h->label);
	} else if(!strncmp(h->bw, "16Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw2meg -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 2MB table", h->host, h->label);
	} else if(!strncmp(h->bw, "32Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw4meg -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 4MB table", h->host, h->label);
	} else if(!strncmp(h->bw, "40Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw5meg -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 5MB table", h->host, h->label);
	} else if(!strncmp(h->bw, "64Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw8meg -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 8MB table", h->host, h->label);
	} else if(!strncmp(h->bw, "80Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw10meg -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 10MB table", h->host, h->label);
	} else if(!strncmp(h->bw, "160Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw20meg -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 20MB table", h->host, h->label);
	} else if(!strncmp(h->bw, "400Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw50meg -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 50MB table", h->host, h->label);
	} else if(!strncmp(h->bw, "1Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t bw1mbps -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 1Mbps table", h->host, h->label);
	} else if(!strncmp(h->bw, "2Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw2mbps -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 2Mbps table", h->host, h->label);
	} else if(!strncmp(h->bw, "4Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw4mbps -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 4Mbps table", h->host, h->label);
	} else if(!strncmp(h->bw, "5Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw5mbps -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 5Mbps table", h->host, h->label);
	} else if(!strncmp(h->bw, "8Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw8mbps -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 8Mbps table", h->host, h->label);
	} else if(!strncmp(h->bw, "10Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw10mbps -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 10Mbps table", h->host, h->label);
	} else if(!strncmp(h->bw, "20Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw20mbps -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 20Mbps table", h->host, h->label);
	} else if(!strncmp(h->bw, "50Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw50mbps -T add %s", PFCTL, h->host);
		syslog(LOG_INFO, "Added host %s(%s) to 50Mbps table", h->host, h->label);
	}

	system(cmd);
	syslog(LOG_INFO, "Added host %s(%s) to PF table", h->host, h->label);
	return 0;
}

/* captive */
	int
remove_line(char *host) 
{
	FILE *fp, *fp2;
	char  h[41];
	char *p, *sp;
	int sec = 0;
	char buf[8192];

	strlcpy(h, host, 40);
	strlcat(h, " ", 40);

	fp = fopen(CONFIG, "r");
	fp2 = fopen("s2.sh", "a");
	sec = 0;
	while(fgets(buf, sizeof(buf), fp)) {
		p = buf;
		if(strchr(p, '}')) {
			sec = 0;
		}
		if(sec) {
			if(strstr(p, h)) {
				continue;
			}
		}
		if( (sp = strstr(p, "captive_hosts {")) ) {
			sec = 1;
		}
		fputs(buf, fp2);

	}    
	fclose(fp);
	fclose(fp2);
	rename("s2.sh", CONFIG);
	chown(CONFIG, 67, 67);
	return 0;
}

/* captive */
void killhost(struct captivehosts *tmp, int reason)
{
	char cmd[8192];

	switch(reason) {
		case REASON_TOTAL_BW_EXCEEDED:
			syslog(LOG_INFO, "Captive Total Bandwidth exceeded for %s (%ld bytes)", tmp->host, tmp->totalcap);
			break;
		case REASON_UPLOAD_BW_EXCEEDED:
			syslog(LOG_INFO, "Captive Upload Bandwidth exceeded for %s (%ld bytes ", tmp->host, tmp->uploadcap);
			break;
		case REASON_DOWNLOAD_BW_EXCEEDED:
			syslog(LOG_INFO, "Captive Download Bandwidth exceeded for %s (%ld bytes)", tmp->host, tmp->dlcap);
			break;
		case REASON_TIMER_EXPIRED:
			syslog(LOG_INFO, "Captive Timer EXPIRED for %s after (%d) seconds", tmp->host, tmp->timealloc);
			break;
	}
	syslog(LOG_INFO, "Deleting host %s from PF table", tmp->host);
	snprintf(cmd, sizeof(cmd), "%s -t captivehosts -T delete %s", PFCTL, tmp->host);
	system(cmd);

	SLIST_REMOVE(&captivehostshead, tmp, captivehosts, next);
	if(!strncmp(tmp->bw, "512kbps", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t bw512kbps -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 512 kbps table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "4096kbps", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw512KB -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 512 KB table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "8Kb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw1meg -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 1MB table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "16Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw2meg -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 2MB table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "32Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw4meg -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 4MB table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "40Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw5meg -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 5MB table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "64Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw8meg -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 8MB table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "80Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw10meg -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 10MB table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "160Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw20meg -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 20MB table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "400Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw50meg -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 50MB table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "1Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t bw1mbps -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 1Mbps table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "2Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw2mbps -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 2Mbps table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "4Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw4mbps -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 4Mbps table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "5Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw5mbps -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 5Mbps table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "8Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw8mbps -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 8Mbps table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "10Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw10mbps -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 10Mbps table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "20Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw20mbps -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 20Mbps table", tmp->host, tmp->label);
	} else if(!strncmp(tmp->bw, "50Mb", 10)) {
		snprintf(cmd, sizeof(cmd), "%s -t  bw50mbps -T delete %s", PFCTL, tmp->host);
		syslog(LOG_INFO, "Deleted host %s(%s) from 50Mbps table", tmp->host, tmp->label);
	}
	remove_line(tmp->host);
	syslog(LOG_INFO, "Deleted host %s from PF table", tmp->host);
	return ;

}

/* captive */
void check_bw_hosts(struct captivehosts *h)
{
	FILE *fp;
	int cnt = -1000;
	unsigned long inbytes = 0, inpkts = 0, outbytes = 0, outpkts = 0, totalbytes = 0;
	char  buf[8192], *p1, *p2, cmd[8192];

	syslog(LOG_INFO, "Checking Host %s for bandwidth usage", h->host);
	snprintf(cmd, sizeof(cmd), "%s -t captivehosts -vTshow", PFCTL);
	fp = popen(cmd, "r");
	while(fgets(buf, sizeof(buf), fp)) {
		buf[strcspn(buf, "\n")] = 0;
		if(strstr(buf, h->host)) {
			cnt = 1;	
		}
		if(cnt == 2) {
			if(strstr(buf, "Cleared")) {
				syslog(LOG_INFO, "Host %s counter cleared", h->host);
				return;
			}
		}
		if(cnt == 4) {
			p1 = strstr(buf, "Packets: ");	
			p2 = strstr(buf, "Bytes: ");	
			p1 += strlen("Packets: ");
			p2 += strlen("Bytes: ");
			sscanf(p1, "%ld", &inpkts);
			sscanf(p2, "%ld", &inbytes);
		}
		if(cnt == 6) {
			p1 = strstr(buf, "Packets: ");	
			p2 = strstr(buf, "Bytes: ");	
			p1 += strlen("Packets: ");
			p2 += strlen("Bytes: ");
			sscanf(p1, "%ld", &outpkts);
			sscanf(p2, "%ld", &outbytes);
			break;
		}
		cnt++;
	}
	syslog(LOG_INFO, " Host %s(%s):: Bytes in: %ld, Pkts in: %ld, Bytes Out: %ld, Pkts out: %ld\n", 
			h->host, h->label, inbytes, inpkts, outbytes, outpkts);

	totalbytes = inbytes + outbytes;

	if(totalbytes >= h->totalcap ) {
		return killhost(h, REASON_TOTAL_BW_EXCEEDED);
	}

	if(outbytes >= h->uploadcap) {
		return killhost(h, REASON_UPLOAD_BW_EXCEEDED);
	}
	if(inbytes >= h->dlcap) {
		return killhost(h, REASON_DOWNLOAD_BW_EXCEEDED);
	}

	syslog(LOG_INFO, "Finished checking Host %s for bandwidth usage", h->host);
	return ;
}

/* captive */
/* This checks data usage every 30seconds (for time based kicking check check_hosts() above )*/
	int 
periodic_wakeup() 
{
	struct captivehosts *tmp;

	SLIST_FOREACH(tmp, &captivehostshead, next) {
		syslog(LOG_INFO, " Captive hosts [%s] %s %s %d %ld %ld %ld %s", tmp->label, tmp->user, tmp->host,
				tmp->duration, tmp->totalcap, tmp->uploadcap, tmp->dlcap, tmp->bw);
		check_bw_hosts(tmp);
	}

	return 0;
}

/* time based */
	int
checkdays(char dayweek)
{
	char buf[1024];
	struct tm *now;
	time_t t;

	t = time(NULL);
	now = localtime(&t);

	strftime(buf, 1024, "%a", now);

	if(dayweek & DAY_SUNDAY) {
		if(strncmp(buf, "Sun", 3) == 0) {
			return 1;
		}
	}
	if(dayweek & DAY_MONDAY) {
		if(strncmp(buf, "Mon", 3) == 0) {
			return 1;
		}

	}
	if(dayweek & DAY_TUESDAY) {
		if(strncmp(buf, "Tue", 3) == 0) {
			return 1;
		}

	}
	if(dayweek & DAY_WEDNESDAY) {
		if(strncmp(buf, "Wed", 3) == 0) {
			return 1;
		}

	}
	if(dayweek & DAY_THURSDAY) {
		if(strncmp(buf, "Thu", 3) == 0) {
			return 1;
		}

	}
	if(dayweek & DAY_FRIDAY) {
		if(strncmp(buf, "Fri", 3) == 0) {
			return 1;
		}

	}
	if(dayweek & DAY_SATURDAY) {
		if(strncmp(buf, "Sat", 3) == 0) {
			return 1;
		}
	}
	return 0;
}

/* time based */
void inserttimerule(struct timebasedrules *t)
{
	char cmd[8192];
	if(!strncmp(t->fwflag, "ALLOW", 5)) {
		syslog(LOG_INFO, "Adding host %s to  ALLOWED PF table", t->host);
		snprintf(cmd, sizeof(cmd), "%s -t timebasedallow -T add %s", PFCTL, t->host);
		system(cmd);
	} else {
		syslog(LOG_INFO, "Adding host %s to DENIED PF table", t->host);
		snprintf(cmd, sizeof(cmd), "%s -t timebaseddeny -T add %s", PFCTL, t->host);
		system(cmd);
	}
	syslog(LOG_INFO, "Added timebased rule host %s to PF table", t->host);
	return;
}

/* time based */
void removetimerule(struct timebasedrules *t)
{
	char cmd[8192];
	if(!strncmp(t->fwflag, "ALLOW", 5)) {
		syslog(LOG_INFO, "Removed host %s from ALLOWED PF table", t->host);
		snprintf(cmd, sizeof(cmd), "%s -t timebasedallow -T delete %s", PFCTL, t->host);
		system(cmd);
	} else {
		syslog(LOG_INFO, "Removed host %s from DENIED PF table", t->host);
		snprintf(cmd, sizeof(cmd), "%s -t timebaseddeny -T delete %s", PFCTL, t->host);
		system(cmd);
	}
	syslog(LOG_INFO, "Removed host %s from PF table", t->host);
	return;

}

/* time based */
int checktimeaccess(struct timebasedrules *t)
{
	char buf[1024];
	struct tm *now;
	time_t to;
	int starthr,startmin, endhr, endmin, nowhr, nowmin;

	to = time(NULL);
	now = localtime(&to);

	strftime(buf, 1024, "%H:%M", now);
	sscanf(buf, "%d:%d", &nowhr, &nowmin);	
	if(strncmp(t->starttime, "ALL", 3) == 0) {
		inserttimerule(t);
	}
	sscanf(t->starttime, "%d:%d", &starthr, &startmin);	
	sscanf(t->endtime, "%d:%d", &endhr, &endmin);	


	if( (nowhr > starthr ) && (nowhr < endhr) ) {
		if( (nowmin > startmin ) && (nowmin < endmin) ) {
			inserttimerule(t);
		} else {
			removetimerule(t);
		}
	} else {
		removetimerule(t);
	}

	return 0;
}
/* common */
void check_timer_hosts(int sig)
{
	struct captivehosts *tmp;
	struct timebasedrules *tmp2;
	int actnow = 0, remaining;

	SLIST_FOREACH(tmp, &captivehostshead, next) {
		if(tmp->duration == 0) {
			continue;
		}
		tmp->duration -= 60;
		tmp->elapsed += 60;
		remaining = tmp->timealloc - tmp->elapsed;

		syslog(LOG_INFO, "Decrementing timer for Captive host %s tot:%d,rem:%d,elapsed:%d", tmp->host, tmp->timealloc, remaining, tmp->elapsed); 
		syslog(LOG_INFO, "Checking Host %s for Captive timer condition", tmp->host);
		if(tmp->duration == 0) {
			killhost(tmp, REASON_TIMER_EXPIRED);
		}
	}

	SLIST_FOREACH(tmp2, &timebasedruleshead, next) {
		actnow = checkdays(tmp2->dayweek);
		if(actnow == 1) {
			checktimeaccess(tmp2);
		}
		syslog(LOG_INFO, "Checking Host %s for time based access", tmp2->host);
	}
	return ;
}

/* Common to both */
int start_timer()
{
	struct itimerval intvl;

	intvl.it_interval.tv_sec = 60;
	intvl.it_interval.tv_usec = 0;

	intvl.it_value.tv_sec = 60;
	intvl.it_value.tv_usec = 0;

	setitimer(ITIMER_REAL, &intvl, NULL);
	signal(SIGALRM, check_timer_hosts);
	return 0;

}


/* captive */
	int
dump_elapsed(int fd)
{
	struct captivehosts *tmp;
	int remaining;
	char foo[1024];

	SLIST_FOREACH(tmp, &captivehostshead, next) {
		if(tmp->timealloc == 0)
			continue;
		remaining = tmp->timealloc - tmp->elapsed;
		snprintf(foo, sizeof(foo), "%s,%s,%d,%d,%d\n", tmp->host, tmp->label, tmp->timealloc,
				remaining, tmp->elapsed);
		write(fd,foo, strlen(foo));
	}
	return 0;
}

/* captive */
	int
dump_bw(int fd)
{
	FILE *fp;
	int cnt = -1000, inbytes, inpkts, outbytes, outpkts;
	char  buf[8192], *p1, *p2, ip[40], cmd[8192], counters[16384], tmpb[1024];
	char ts[1024];

	snprintf(cmd, sizeof(cmd), "%s -t captivehosts -vTshow", PFCTL);
	fp = popen(cmd, "r");
	memset(counters, 0, sizeof(counters));
	while(fgets(buf, sizeof(buf), fp)) {
		buf[strcspn(buf, "\n")] = 0;
		if(strlen(buf) <= 43) {
			strlcpy(ip, buf, 40);
			cnt = 1;	
		}
		if(cnt == 2) {
			p1 = strstr(buf, "Cleared:");
			strlcpy(ts, p1 + 20, sizeof(ts));

		}
		if(cnt == 3) {
			if(strlen(buf) <= 43) {
				syslog(LOG_INFO, "Host %s counter cleared", ip);
				snprintf(tmpb, sizeof(tmpb), "%s,%s,%d,%d,%d,%d\n", 
						ip, ts, 0, 0, 0, 0);
				strlcat(counters, tmpb, sizeof(counters));
				cnt = -1000;
			}
		}
		if(cnt == 4) {
			p1 = strstr(buf, "Packets: ");	
			p2 = strstr(buf, "Bytes: ");	
			p1 += strlen("Packets: ");
			p2 += strlen("Bytes: ");
			sscanf(p1, "%d", &inpkts);
			sscanf(p2, "%d", &inbytes);
		}
		if(cnt == 6) {
			p1 = strstr(buf, "Packets: ");	
			p2 = strstr(buf, "Bytes: ");	
			p1 += strlen("Packets: ");
			p2 += strlen("Bytes: ");
			sscanf(p1, "%d", &outpkts);
			sscanf(p2, "%d", &outbytes);
			snprintf(tmpb, sizeof(tmpb), "%s,%s,%d,%d,%d,%d\n", 
					ip, ts, inpkts, inbytes, outpkts, outbytes);
			strlcat(counters, tmpb, sizeof(counters));
			cnt = -1000;
		}
		cnt++;
	}
	write(fd, counters, strlen(counters));
	syslog(LOG_INFO, "Dumped stats to UNIX sock");
	return 0;
}

/* XXX code that processes the commands on UNIX socket */  
	int
reactunix(int fd, char *buf, int n)
{
	char *cmd, cmdswitch[8192];

	cmd = strchr(buf, '\n');
	strlcpy(cmdswitch, buf, cmd - buf + 1);
	syslog(LOG_INFO, "[%s]", cmdswitch);

	if(!strcmp(cmdswitch, "DUMP_BW")) {
		syslog(LOG_INFO, "processing DUMP_BW...");
		dump_bw(fd);
	} else if(!strcmp(cmdswitch, "DUMP_ELAPSED")) {
		syslog(LOG_INFO, "processing DUMP_ELAPSED...");
		dump_elapsed(fd);
	} else {
		syslog(LOG_INFO, "Unrecognized command from UNIX socket in reactunix()");
	}
	close(fd);
	return 0;
}

	int
start_captive()
{
	int unixsock, unixacc;
	int n,  t, done, off;
	char buf[8192];
	struct sockaddr_un local, remote;
	struct pollfd pfd[2];
	char *p2, unixcmd[8192];
	int len, retval;

	if ((unixsock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		syslog(LOG_ERR, "Could not open UNIX domain socket %s",
				SOCK_PATH);
		exit(1);
	}

	local.sun_family = AF_UNIX;
	strlcpy(local.sun_path, SOCK_PATH, sizeof(local.sun_path));
	unlink(local.sun_path);
	len = sizeof(struct sockaddr_un);
	if (bind(unixsock, (struct sockaddr *)&local, len) == -1) {
		perror("bind UNIX socket");
		syslog(LOG_ERR, "Could not bind UNIX domain socket %s",
				SOCK_PATH);
		exit(1);
	}
	chmod(SOCK_PATH, 0666);
	if (listen(unixsock, 5) == -1) {
		perror("listen");
		syslog(LOG_ERR, 
				"Could not listen on UNIX domain socket %s", SOCK_PATH);
		exit(1);
	}


	pfd[0].fd = unixsock;
	pfd[0].events = POLLIN;

	for(;;) {

		syslog(LOG_INFO, "Listening for captive portal");

		/* Poll(2) with a 30 sec timeout */
		retval = poll(pfd, 1, 30000);

		/* timeout, so let us check the hosts now */
		if(retval == 0) {
			periodic_wakeup();
		}

		/* XXX Config UNIX socket */
		if(pfd[0].revents & POLLIN) {
			t = sizeof(remote);
			if ((unixacc = accept(pfd[0].fd , (struct sockaddr *)&remote, &t)) == -1) {
				perror("UNIX accept");
				exit(1);
			}

			syslog(LOG_INFO, "Connected on UNIX domain socket.\n");
			done = 0;
			n = 0;
			off = 0;
			bzero(unixcmd, sizeof(unixcmd));
			do {
				n = recv(unixacc, buf, sizeof(buf), 0);
				buf[n] = 0;
				strlcat(unixcmd + off, buf, sizeof(unixcmd));
				if( (p2 = strstr(unixcmd, ".\n")) ){
					*p2 = 0;	
					done = 1;
					syslog(LOG_INFO, "Detected EOF in UNIX sock");
					break;
				}
				if (n <= 0) {
					if (n < 0) perror("recv");
					done = 1;
				}
				off += n - 1;
			} while (!done);

			syslog(LOG_INFO, "Received [%s] from UNIX sock", unixcmd);
			reactunix(unixacc, unixcmd, strlen(unixcmd));
			close(unixacc);
			continue;
		}

		syslog(LOG_INFO, "Going back to listen...");
	} 
	return 0;
}

	int
main()
{
	pid_t pid;
	openlog("start_captive_timebased",  LOG_PID|LOG_PERROR, LOG_LOCAL3);
	syslog(LOG_INFO, "Starting Captive Deamon process...");


	signal(SIGCHLD, waitforkidandkill);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, configparse);

	syslog(LOG_INFO, "Doing Config parsing ");
	configparse(1);
	syslog(LOG_INFO, "Config parse done");

	start_timer();
	start_captive();
	daemon(0, 0);
	pid = fork();

	if(pid != 0) { /* Parent */
	} else {/* Child */
		start_timer();
		start_captive();
	}
	/* NOTREACHED */
	return 0;
}
