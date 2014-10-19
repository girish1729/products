
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <err.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <regex.h>
#include <sys/queue.h>
#include <sys/queue.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <getopt.h>
#include <netdb.h>
#include <libpq-fe.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>

#include "p0f-query.h"

/* Macros */

#define HELOREJECT -3
#define FQDNREJECT -4
#define RFCREJECT -5
#define SPFREJECT -8
#define SURBLREJECT -10
#define LOCALMAIL 30
#define AUTHREJ -14
#define DROPPED -120
#define PARTIALWRITE -140

#define debug(x...) fprintf(stderr,x)
#define fatal(x...) do { debug("[-] ERROR: " x); exit(2); } while (0)
#define pfatal(x)   do { debug("[-] ERROR: "); perror(x); exit(2); } while (0)
#define TRUE 1
#define FALSE 0

#define SCCONFIG "/etc/sc.conf"

/* Start p0f like this:
 *
 * p0f -Q /tmp/p0fsock -q -l -d -o /dev/null -0 tcp dst port 25
 */

struct sc_parms {
	char rfccomp;
	char helocheck;
	char stricthelocheck;
	char reqfqdn;
	char spfcheck;
	char stopscanonvirus;
	char spamact;
	char virusact;
	char banattact;
	char virusenable;
	char spamenable;
	char regexenable;
	char notifset;
	char notifyadmin;
	char notifyuser;
	char discset;
	char quaadmin[1024];

} sc_parms;

static struct disclaim {
	char body[8192];
} disclaim;

static struct bannedattachmail {
	char sub[1024];
	char body[8192];
} bannedattachmail;

static struct bannedsendermail {
	char sub[1024];
	char body[8192];
} bannedsendermail;

static struct bannedrecipmail {
	char sub[1024];
	char body[8192];
} bannedrecipmail;

static struct bannedmimemail {
	char sub[1024];
	char body[8192];
} bannedmimemail;

static struct mailszexceedmail {
	char sub[1024];
	char body[8192];
} mailszexceedmail;

static struct virussendermail {
	char sub[1024];
	char body[8192];
} virussendermail;

static struct virusrecipmail {
	char sub[1024];
	char body[8192];
} virusrecipmail;

struct matchre {
	char pat[1024];
	char type[1024]; /* One of header , body, sender, recip, attach */
	int flag; /* reject mail or accept mail on match*/
} matchre;

static struct mailfromus {
	char to[1024];
	char sub[1024];
	char body[8192];
} mailfromus;

struct bannedsenderids {
	char mailid[1024];
	SLIST_ENTRY(bannedsenderids) next;
} bannedsenderids;

struct bannedrecipids {
	char mailid[1024];
	SLIST_ENTRY(bannedrecipids) next;
} bannedrecipids;

/* XXX quarantine blacklist and whitelist */

struct disclaimexcept {
	char mailid[1024];
	SLIST_ENTRY(disclaimexcept) next;
} ;

struct allowedmime {
	char mime[1024];
	SLIST_ENTRY(allowedmime) next;
} allowedmime;

struct bannedmime {
	char mime[1024];
	SLIST_ENTRY(bannedmime) next;
} bannedmime;

struct heloexcept {
	char helo[1024];
	SLIST_ENTRY(heloexcept) next;
} heloexcept;

static SLIST_HEAD(, disclaimexcept) disclaimhead;
static SLIST_HEAD(, bannedsenderids) bannedsendershead;
static SLIST_HEAD(, bannedrecipids) bannedreciphead;
static SLIST_HEAD(, allowedmime) allowedmimehead;
static SLIST_HEAD(, bannedmime) bannedmimehead;
static SLIST_HEAD(, heloexcept) heloexcepthead;

/* All our mail statistics counters */
static struct globalcnt {
	int totalmailcnt;
	int goodmailcnt;
	int numattcnt;
	int matchrecnt;
	int viruscnt;
	int spamcnt;
	int bannednetcnt;
	int bannedsendercnt;
	int bannedrecipcnt;
	int bannedattcnt;
	int bannedmimecnt;
	int rfcrejcnt;
	int fqdnrejcnt;
	int dkimrejcnt;
	int spfrejcnt;
	int helorejcnt;
	int surblrejcnt;
	int razorrejcnt;
	int mailszcnt;
} globalcnt;

enum act {
	PASS=1,
	QUARANTINE,
	REJECT
} act;

enum reason {
	BLOCKED_ATTACH = 1,
	SIZE_EXCEEDED,
	BLOCKED_SENDER,
	BLOCKED_SENDER_QUARANTINE,
	BLOCKED_RECIP,
	BLOCKED_DENIED_NETWORK,
	BLOCKED_NOT_ALLOWED_NETWORK,
	BLOCKED_MIME,
	VIRUS_FOUND,
	RAZOR_SPAM_FOUND,
	BOGOFILTER_SPAM_FOUND,
	BMF_SPAM_FOUND,
	RELAYDB_SPAM_FOUND,
	REGEX_MATCH

} reason;


#define SOCK_PATH "/tmp/proxysock"

#define GLOB_PATH "/tmp/.stats"

char *searchpats[] = {
	"^From:",
	"^To:",
	"^Subject:",
	"^Date:",
	"^Message-id:",
	NULL
};

char *researchpats[] = {
	"^Subject:",
	"^Date:",
	"^Message-id:",
	NULL
};

/* Some globals */
char 	envip[1024], 
	osfp[1024],
	helostring[1024],
	mailqid[1024],
	envfrom[1024], 
	envto[1024], 
	subject[1024], 
	toid[1024], 
	fromid[1024], 
	date[1024], 
	msgid[1024], 
	headers[16384],
	mailattr[8192],
	ourpublic[40],
	ourlocal[40],
	tmpmailname[1024];

/* Default mail size of 100 MB */
int maxmailsz = 104857600;
int dropmail = 0;
int tlsmail = 0, regextype;
int bypassbmf = 0;
int insertqua = 0;
char quafile[1024], quareason[1024];
off_t mailsz;
char mimes[8192];

/* XXX Function prototypes */
void configparse(int sig);
int insert_quadb(int);
int updateglobalcnt(void);
int mimecheck(void);
int spfquery(void);
int match_addr(char *net, u_int32_t testip);
int dropmailnotify(void) ;

/* XXX code starts here */

int copyblock(char *parm, char *lines)
{	char *p, *sep;
	struct bannedsenderids *tmp;
	struct disclaimexcept *tmp2;
	struct bannedrecipids *tmp3;
	struct allowedmime *almime;
	struct bannedmime *blmime;
	
 	if(!strcmp(parm, "disclaimerexcept")) {
		while (!SLIST_EMPTY(&disclaimhead)) {           /* Delete. */
			tmp2 = SLIST_FIRST(&disclaimhead);
			SLIST_REMOVE_HEAD(&disclaimhead, next);
			free(tmp2);
		}

		p = strndup(lines, 16384);
		while( (sep = strsep(&p, "\n")) ) {
			if(strlen(sep) == 0)
				continue;
			tmp2 = malloc(sizeof(struct disclaimexcept));
			strncpy(tmp2->mailid, sep, sizeof(tmp2->mailid));
			SLIST_INSERT_HEAD(&disclaimhead, tmp2, next);
		} 
		free(p);
		SLIST_FOREACH(tmp2, &disclaimhead, next) {
			syslog(LOG_INFO, " Disclaimer exceptions [%s]", tmp2->mailid);
		}
	} else if(!strcmp(parm, "allowedmime")) {
		while (!SLIST_EMPTY(&allowedmimehead)) {           /* Delete. */
			almime = SLIST_FIRST(&allowedmimehead);
			SLIST_REMOVE_HEAD(&allowedmimehead, next);
			free(almime);
		}
		p = strndup(lines, 16384);
		while( (sep = strsep(&p, "\n")) ) {
			if(strlen(sep) == 0)
				continue;
			almime = malloc(sizeof(struct allowedmime));
			strncpy(almime->mime, sep, sizeof(almime->mime));
			SLIST_INSERT_HEAD(&allowedmimehead, almime, next);
		}
		free(p);
		SLIST_FOREACH(almime, &allowedmimehead, next) {
			syslog(LOG_INFO, "Allowed MIME  [%s]", almime->mime);
		}
		
	} else if(!strcmp(parm, "bannedmime")) {
		while (!SLIST_EMPTY(&bannedmimehead)) {           /* Delete. */
			blmime = SLIST_FIRST(&bannedmimehead);
			SLIST_REMOVE_HEAD(&bannedmimehead, next);
			free(blmime);
		}
		p = strndup(lines, 16384);
		while( (sep = strsep(&p, "\n")) ) {
			if(strlen(sep) == 0)
				continue;
			blmime = malloc(sizeof(struct bannedmime));
			strncpy(blmime->mime, sep, sizeof(blmime->mime));
			SLIST_INSERT_HEAD(&bannedmimehead, blmime, next);
		}
		free(p);
		SLIST_FOREACH(blmime, &bannedmimehead, next) {
			syslog(LOG_INFO, "Banned  MIME [%s]", blmime->mime);
		}
	} else if(!strcmp(parm, "bannedsender")) {
		while (!SLIST_EMPTY(&bannedsendershead)) {           /* Delete. */
			tmp = SLIST_FIRST(&bannedsendershead);
			SLIST_REMOVE_HEAD(&bannedsendershead, next);
			free(tmp);
		}
		p = strndup(lines, 16384);
		while( (sep = strsep(&p, "\n")) ) {
			if(strlen(sep) == 0)
				continue;
			tmp = malloc(sizeof(struct bannedsenderids));
			strncpy(tmp->mailid, sep, sizeof(tmp->mailid));
			SLIST_INSERT_HEAD(&bannedsendershead, tmp, next);
		}
		free(p);
		SLIST_FOREACH(tmp, &bannedsendershead, next) {
			syslog(LOG_INFO, "banned sender [%s]", tmp->mailid);
		}
	} else if(!strcmp(parm, "bannedrecip")) {
		while (!SLIST_EMPTY(&bannedreciphead)) {           /* Delete. */
			tmp3 = SLIST_FIRST(&bannedreciphead);
			SLIST_REMOVE_HEAD(&bannedreciphead, next);
			free(tmp3);
		}
		p = strndup(lines, 16384);
		while( (sep = strsep(&p, "\n")) ) {
			if(strlen(sep) == 0)
				continue;
			tmp3 = malloc(sizeof(struct bannedrecipids));
			strncpy(tmp3->mailid, sep, sizeof(tmp3->mailid));
			SLIST_INSERT_HEAD(&bannedreciphead, tmp3, next);
		}
		free(p);
		SLIST_FOREACH(tmp3, &bannedreciphead, next) {
			syslog(LOG_INFO, " banned recip [%s]", tmp3->mailid);
		}
	} else if(!strcmp(parm, "virussendermail")) {
		strncpy(virussendermail.body, lines, 8192);
		syslog(LOG_INFO, " Virus sender body[%s]", virussendermail.body);
	} else if(!strcmp(parm, "virusrecipmail")) {
		strncpy(virusrecipmail.body, lines, 8192);
		syslog(LOG_INFO, " Virus recipient body[%s]", virusrecipmail.body);
	} else if(!strcmp(parm, "bannedattachmail")) {
		strncpy(bannedattachmail.body, lines, 8192);
		syslog(LOG_INFO, " Banned attachment body[%s]", bannedattachmail.body);
	} else if(!strcmp(parm, "mailszexceedmail")) {
		strncpy(mailszexceedmail.body, lines, 8192);
		syslog(LOG_INFO, " Mail Size Exceed body[%s]", mailszexceedmail.body);
	}
	return 0;
}

/* Config file parsing of sc.conf */

int copyvals(char *parm, char *val)
{
	if(!strcmp(parm, "helocheck")) {
		if(strstr(val, "yes")) {
			syslog(LOG_INFO, "HELO check enabled in sc.conf");
			sc_parms.helocheck = 1;	
		} else {
			sc_parms.helocheck = 0;	
			syslog(LOG_INFO, "HELO check disabled in sc.conf");
		}
	} else if(!strcmp(parm, "stricthelocheck")) {
		if(strstr(val, "yes")) {
			syslog(LOG_INFO, "Strict HELO check enabled in sc.conf");
			sc_parms.stricthelocheck = 1;	
		} else {
			sc_parms.stricthelocheck = 0;	
			syslog(LOG_INFO, "Strict HELO check disabled in sc.conf");
		}
	} else if(!strcmp(parm, "reqfqdn")) {
		if(strstr(val, "yes")) {
			sc_parms.reqfqdn = 1;
			syslog(LOG_INFO, "FQDN check disabled in sc.conf");
		} else {
			sc_parms.reqfqdn = 0;
			syslog(LOG_INFO, "FQDN check disabled in sc.conf");
		}
	} else if(!strcmp(parm, "spfcheck")) {
		if(strstr(val, "yes")) {
			sc_parms.spfcheck = 1;
			syslog(LOG_INFO, "SPF check enabled in sc.conf");
		} else {
			sc_parms.spfcheck = 0;
			syslog(LOG_INFO, "SPF check disabled in sc.conf");
		} 
	} else if(!strcmp(parm, "outdisclaimerflag")) {
		if(strstr(val, "yes")) {
			sc_parms.spfcheck = 1;
			syslog(LOG_INFO, "E-mail disclaimer enabled in sc.conf");
		} else {
			sc_parms.spfcheck = 0;
			syslog(LOG_INFO, "E-mail disclaimer disabled in sc.conf");
		} 

	} else if(!strcmp(parm, "notificationflag")) {
		if(strstr(val, "yes")) {
			sc_parms.spfcheck = 1;
			syslog(LOG_INFO, "E-mail notification enabled in sc.conf");
		} else {
			sc_parms.spfcheck = 0;
			syslog(LOG_INFO, "E-mail notifications disabled in sc.conf");
		} 
	} else if(!strcmp(parm, "notifyuser")) {
		if(strstr(val, "yes")) {
			sc_parms.notifyuser = 1;
			syslog(LOG_INFO, "Notify user enabled in sc.conf");
		} else {
			sc_parms.notifyuser = 0;
			syslog(LOG_INFO, "Notify user disabled in sc.conf");
		} 
	} else if(!strcmp(parm, "notifyadmin")) {
		if(strstr(val, "yes")) {
			sc_parms.notifyadmin = 1;
			syslog(LOG_INFO, "Notify admin enabled in sc.conf");
		} else {
			sc_parms.notifyadmin = 0;
			syslog(LOG_INFO, "Notify admin disabled in sc.conf");
		} 
	} else if(!strcmp(parm, "stopscanonvirus")) {
		if(strstr(val, "yes")) {
			sc_parms.stopscanonvirus = 1;
			syslog(LOG_INFO, "Stop scanning if virus found");
		} else {
			sc_parms.stopscanonvirus = 0;
			syslog(LOG_INFO, "Continue if virus found");
		}

	} else if(!strcmp(parm, "virusfilt")) {
		if(strstr(val, "yes")) {
			sc_parms.virusenable = 1;
			syslog(LOG_INFO, "Virus scanning is enabled");
		} else {
			sc_parms.virusenable = 0;
			syslog(LOG_INFO, "Virus scanning is disabled");
		}
	} else if(!strcmp(parm, "spamfilt")) {
		if(strstr(val, "yes")) {
			sc_parms.spamenable = 1;
			syslog(LOG_INFO, "Spam filtering is enabled");
		} else {
			sc_parms.spamenable = 0;
			syslog(LOG_INFO, "Spam filtering is disabled");
		}
	} else if(!strcmp(parm, "notificationflag")) {
		if(strstr(val, "yes")) {
			sc_parms.notifset = 1;
			syslog(LOG_INFO, "Notifications are enabled");
		} else {
			sc_parms.notifset = 0;
			syslog(LOG_INFO, "Notifications are disabled");
		}
	} else if(!strcmp(parm, "regex_enable")) {
		if(strstr(val, "yes")) {
			sc_parms.regexenable = 1;
			syslog(LOG_INFO, "REGEX filtering is enabled");
		} else {
			sc_parms.regexenable = 0;
			syslog(LOG_INFO, "REGEX filtering is disabled");
		}
	} else if(!strcmp(parm, "regex_pattern")) {
		strncpy(matchre.pat , val, sizeof(matchre.pat));
		syslog(LOG_INFO, "REGEX pattern is [%s]", val);
	} else if(!strcmp(parm, "regex_type")) {
		strncpy(matchre.type , val, sizeof(matchre.type));
		syslog(LOG_INFO, "REGEX type is [%s]", val);
	} else if(!strcmp(parm, "regex_flag")) {
		matchre.flag = strcmp(val, "allow") == 0 ? 0: 1; 
		syslog(LOG_INFO, "REGEX flag is [%s]", val);
	} else if(!strcmp(parm, "virusact")) {
		if(strstr(val, "pass")) {
			sc_parms.virusact = PASS;
			syslog(LOG_INFO, "Virus mails are passed");
		} else if(strstr(val, "qua")) {
			sc_parms.virusact = QUARANTINE;
			syslog(LOG_INFO, "Virus mails are Quarantined");
		} else if(strstr(val, "rej")) {
			sc_parms.virusact = REJECT;
			syslog(LOG_INFO, "Virus mails are Rejected");
		}
	} else if(!strcmp(parm, "spamact")) {
		if(strstr(val, "pass")) {
			sc_parms.spamact = PASS;
			syslog(LOG_INFO, "Spam mails are passed");
		} else if(strstr(val, "qua")) {
			sc_parms.spamact = QUARANTINE;
			syslog(LOG_INFO, "Spam mails are Quarantined");
		} else if(strstr(val, "rej")) {
			sc_parms.spamact = REJECT;
			syslog(LOG_INFO, "Spam mails are Rejected");
		}
	} else if(!strcmp(parm, "outdisclaimerflag")) {
		if(strstr(val, "yes")) {
			sc_parms.discset = 1;
			syslog(LOG_INFO, " Disclaimers are enabled");
		} else {
			sc_parms.discset = 0;
			syslog(LOG_INFO, " Disclaimers are disabled");
		}
	} else if(!strcmp(parm, "quaadmin")) {
		strncpy(sc_parms.quaadmin, val, 1024);
		syslog(LOG_INFO, " Quarantine notify admin is [%s],", sc_parms.quaadmin);
	} else if(!strcmp(parm, "bannedattachsub")) {
		strncpy(bannedattachmail.sub,  parm, 1024);
	} else if(!strcmp(parm, "bannedsendersub")) {
		strncpy(bannedsendermail.sub,   parm, 1024);
	} else if(!strcmp(parm, "bannedrecipsub")) {
		strncpy(bannedrecipmail.sub,   parm, 1024);
	} else if(!strcmp(parm, "mailszexceedsub")) {
		strncpy(mailszexceedmail.sub,   parm, 1024);
	} else if(!strcmp(parm, "virussendersub")) {
		strncpy(virussendermail.sub,  parm, 1024);
	} else if(!strcmp(parm, "virusrecipsub")) {
		strncpy(virusrecipmail.sub,    parm, 1024);
	} else {
		syslog(LOG_INFO, " Got unrecognized parm [%s] ", parm);
	}

	return 0;
}

void
configparse(int sig)
{
	int cfd, b, sec = 0;
	char *p, *copy, *t, *sp;
	char  buf[16384], blockbuf[16384];
	char parm[1024], val[1024];

	cfd = open(SCCONFIG, O_RDONLY);
	if(cfd == -1) {
		perror("open");
		syslog(LOG_ERR, "Cannot open config file");
	}

	SLIST_INIT(&allowedmimehead);
	SLIST_INIT(&bannedmimehead);
	SLIST_INIT(&disclaimhead);
	SLIST_INIT(&bannedsendershead);
	SLIST_INIT(&bannedreciphead);
	SLIST_INIT(&heloexcepthead);

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
				parm[0] = 0;
				continue;
			}
			if(sec) {
				strncat(blockbuf, p, sizeof(blockbuf));
				strncat(blockbuf, "\n", sizeof(blockbuf));
				continue;
			}
			if( (sp = strchr(p, '{')) ) {
				strncpy(parm, p, sp - p);
				parm[sp-p-1] = 0;
				sec = 1;
				continue;
			}
			sp = strchr(p, ' ');
			if(sp) {
				strncpy(parm , p, sp - p + 1); 
				parm[sp-p] = 0;
				strncpy(val, sp + 1, sizeof(val));
				copyvals(parm, val);
			}
		}    
		free(t);
	}    
	close(cfd);
	signal(SIGHUP, configparse);
	return;
}

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

/* Run every 24 hours to clear counters */

void resetcounters(int sig) {
	globalcnt.totalmailcnt = 0;
	globalcnt.numattcnt = 0;
	globalcnt.matchrecnt = 0;
	globalcnt.viruscnt = 0;
	globalcnt.spamcnt = 0;
	globalcnt.bannednetcnt = 0;
	globalcnt.bannedsendercnt = 0;
	globalcnt.bannedrecipcnt = 0;
	globalcnt.bannedattcnt = 0;
	globalcnt.bannedmimecnt = 0;
	globalcnt.rfcrejcnt = 0;
	globalcnt.fqdnrejcnt = 0;
	globalcnt.dkimrejcnt = 0;
	globalcnt.helorejcnt = 0;
	globalcnt.surblrejcnt = 0;
	globalcnt.razorrejcnt = 0;
	globalcnt.spfrejcnt = 0;
	globalcnt.goodmailcnt = 0;
	globalcnt.mailszcnt = 0;

}

	int
updateglobalcnt()
{
	int  ret;
	int connsock;
	struct sockaddr_un local;

	if ((connsock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		printf( "Could not open UNIX domain socket %s", GLOB_PATH);
		return -1;
	}
	local.sun_family = AF_UNIX;
	strncpy(local.sun_path, GLOB_PATH, sizeof(local.sun_path));
	ret = connect(connsock, (struct sockaddr *)&local, SUN_LEN(&local));
	if(ret < 0) {
		perror("connect");
		syslog(LOG_ERR, "Connect to GLOBALCNT socket failed");
		return -1;
	}

	ret = write(connsock, &globalcnt, sizeof(globalcnt));
	if(ret <= 0) {
		syslog(LOG_ERR, "Write to GLOBALCNT socket failed");
		return -1;

	}
	close(connsock);
	return 0;
}

/* Find out the public IP from a NAT local RFC1918 IP address */
/*
	int
ournatip_query(struct sockaddr_in *client)
{
	struct pfioc_natlook pnl; 
	u_int32_t ip, ip2;
	int pfdev;

	memset(&pnl, 0, sizeof pnl);
	pnl.direction = PF_OUT;
	pnl.af = AF_INET;
	pnl.proto = IPPROTO_TCP;
	syslog(LOG_INFO, "Doing NAT lookup");
	memcpy(&pnl.saddr.v4, &client->sin_addr.s_addr, 
			sizeof pnl.saddr.v4);

	ip = inet_addr("127.0.0.1");
	ip2 = client->sin_addr.s_addr;
	if(ip == ip2) {
		syslog(LOG_INFO, "Not looking up local address");
		return -1;
	}
	memcpy(&pnl.daddr.v4, &ip, sizeof pnl.daddr.v4);
	pnl.sport = client->sin_port;
	pnl.dport = htons(7000);

	pfdev = open("/dev/pf", O_RDONLY);
	if(pfdev == -1) {
		perror("open(2) of pf(4)/");
		syslog(LOG_ERR, "Could not open /dev/pf");
		return (-1);
	}
	if (ioctl(pfdev, DIOCNATLOOK, &pnl) == -1) {
		perror("ioctl(2)");
		syslog(LOG_ERR, "ioctl() for NAT lookup failed");
		return (-1);
	}
	close(pfdev);

	strncpy(ourlocal, inet_ntoa(pnl.rdaddr.v4), sizeof(ourlocal));
	syslog(LOG_INFO, "Got SMTP request");

	return (0); 
}
*/

	int
dumpstats(int fd)
{

	char stats[8192], t[8192];
	struct globalcnt *gl;
	gl = &globalcnt;

	bzero(stats, sizeof(stats));
	snprintf(t, sizeof(t), "totalmailcnt=%d\n", gl->totalmailcnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "goodmailcnt=%d\n", gl->goodmailcnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "numattcnt=%d\n", gl->numattcnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "matchrecnt=%d\n", gl->matchrecnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "viruscnt=%d\n", gl->viruscnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "spamcnt=%d\n", gl->spamcnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "bannednetcnt=%d\n", gl->bannednetcnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "bannedsendercnt=%d\n", gl->bannedsendercnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "bannedrecipcnt=%d\n", gl->bannedrecipcnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "bannedattcnt=%d\n", gl->bannedattcnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "bannedmimecnt=%d\n", gl->bannedmimecnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "rfcrejcnt=%d\n", gl->rfcrejcnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "fqdnrejcnt=%d\n", gl->fqdnrejcnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "dkimrejcnt=%d\n", gl->dkimrejcnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "spfrejcnt=%d\n", gl->spfrejcnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "helorejcnt=%d\n", gl->helorejcnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "surblrejcnt=%d\n", gl->surblrejcnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "razorrejcnt=%d\n", gl->razorrejcnt);
	strncat(stats, t, sizeof(stats));
	snprintf(t, sizeof(t), "mailszcnt=%d\n", gl->mailszcnt);
	strncat(stats, t, sizeof(stats));

	syslog(LOG_INFO, "Dumping stats to UNIX sock");
	write(fd, stats, strlen(stats));
	return 0;
}

/* XXX the code the sends e-mail... */
	int
send_mail(struct mailfromus *p)
{
	char buf[8192], recip[1024];
	int fd;

	strncpy(recip, p->to, sizeof(toid));
	recip[0] = ' ';
	recip[strlen(recip) - 1] = 0;
	snprintf(buf, sizeof(buf), 
			"export EMAIL=\"SpamCheetah <noreply@sc.com>\"" \
			";/usr/bin/mutt -s %s %s < /tmp/.m", p->sub, recip);
	fd = open("/tmp/.m", O_WRONLY | O_CREAT | O_TRUNC, 0646);
	if(fd == -1) {
		syslog(LOG_ERR, "open(2) for sending mail");
		unlink(tmpmailname);
		exit(128);
	}
	write(fd, p->body, strlen(p->body));
	close(fd);
	syslog(LOG_INFO, "Buffer is [%s]", buf);
	system(buf);
	unlink("/tmp/.m");
	syslog(LOG_INFO, "Mail sent");
	return 0;
}

	int
notify_virus_sender(void)
{

	strncpy(mailfromus.to, envfrom, sizeof(mailfromus.to));
	strncpy(mailfromus.sub, virussendermail.sub, sizeof(mailfromus.sub));
	strncpy(mailfromus.body, virussendermail.body, sizeof(mailfromus.body));
	send_mail(&mailfromus);
	syslog(LOG_INFO, "Notifying virus sender");
	return 0;
}

	int
notify_virus_recip(void)
{
	struct mailfromus m;

	strncpy(m.to, envto, sizeof(m.to));
	strncpy(m.sub, virusrecipmail.sub, sizeof(m.sub));
	strncpy(m.body, virusrecipmail.body, sizeof(m.body));
	send_mail(&m);
	syslog(LOG_INFO, "Notifying virus recipient");
	return 0;
}

	int
notify_blocked_sender(void)
{
	struct mailfromus m;

	strncpy(m.to, envfrom, sizeof(m.to));
	strncpy(m.sub, bannedsendermail.sub, sizeof(m.sub));
	strncpy(m.body, bannedsendermail.body, sizeof(m.body));
	send_mail(&m);
	syslog(LOG_INFO, "Notifying blocked sender");
	return 0;
}

	int
notify_blocked_mime(void)
{
	struct mailfromus m;

	strncpy(m.to, envfrom, sizeof(m.to));
	strncpy(m.sub, bannedmimemail.sub, sizeof(m.sub));
	strncpy(m.body, bannedmimemail.body, sizeof(m.body));
	send_mail(&m);
	syslog(LOG_INFO, "Notifying blocked MIME");
	return 0;
}

	int
notify_blocked_recip(void)
{
	struct mailfromus m;

	strncpy(m.to, envfrom, sizeof(m.to));
	strncpy(m.sub, bannedrecipmail.sub, sizeof(m.sub));
	strncpy(m.body, bannedrecipmail.body, sizeof(m.body));
	send_mail(&m);
	syslog(LOG_INFO, "Notifying blocked recipient");
	return 0;
}

	int
notify_blocked_attach(void)
{
	struct mailfromus m;

	strncpy(m.to, envfrom, sizeof(m.to));
	strncpy(m.sub, bannedattachmail.sub, sizeof(m.sub));
	strncpy(m.body, bannedattachmail.body, sizeof(m.body));
	send_mail(&m);
	syslog(LOG_INFO, "Notifying blocked attachment");

	return 0;
}
	int
notify_size_exceeded(void)
{
	struct mailfromus m;

	strncpy(m.to, envfrom, sizeof(m.to));
	strncpy(m.sub, mailszexceedmail.sub, sizeof(m.sub));
	strncpy(m.body, mailszexceedmail.body, sizeof(m.body));
	send_mail(&m);
	syslog(LOG_INFO, "Notifying blocked attachment");

	return 0;
}
	int
fqdncheck(char *helo)
{
	if(strchr(helo, '.'))
		return 0;
	else 
		globalcnt.fqdnrejcnt++;

	updateglobalcnt();
	return FQDNREJECT;
}

	int
rfccheck(char *mailfrom)
{

	char *copy, *p, *tmp;

	if(mailfrom == NULL) {
		globalcnt.rfcrejcnt++;
		updateglobalcnt();
		syslog(LOG_INFO, "SMTP RFC 2821:: Blank mail ID in ENV From");
		return RFCREJECT;
	}
	p = strchr(mailfrom, '@') + 1;

	if(p == NULL) {
		globalcnt.rfcrejcnt++;
		updateglobalcnt();
		syslog(LOG_INFO, "SMTP RFC 2821:: No @ character in mail ID");
		return RFCREJECT;
	}

	copy = strdup(p);
	tmp = copy;
	p = copy;
	*strchr(copy, '>') = 0;
	if(*p == '-' || !isalnum(*p)) {
		globalcnt.rfcrejcnt++;
		updateglobalcnt();
		syslog(LOG_INFO, "SMTP RFC 2821:: Invalid HOST domain in mail from\n");
		return RFCREJECT;
	}
	if(!strchr(p, '.')) {
		globalcnt.rfcrejcnt++;
		updateglobalcnt();
		syslog(LOG_INFO, "SMTP RFC 2821:: No FQDN in from id\n");
		return RFCREJECT;
	}
	while(*++p) {
		if(!isalnum(*p)) {

			if(*p == '-' || *p == '_' || *p == '.')
				continue;
			else {
				globalcnt.rfcrejcnt++;
				updateglobalcnt();
				syslog(LOG_INFO, "SMTP RFC 2821:: [%c] Bad Host name in ENV From\n", *p);
				return RFCREJECT;
			}
		}
	}
	free(tmp);
	return 0;
}

int
netmatchhelo(char *ip) {
	char net[1024];

	snprintf(net, sizeof(net), "%s/24", envip);
	return match_addr(net, inet_addr(ip));

}

int
matchhelo(char *ip) {
	if(sc_parms.stricthelocheck == 1) {
		if(!strcmp(envip, ip)) 
			return 0;
	} else {
		if(!netmatchhelo(ip))
			return 0;
	}
	return 1;
}

int
helocheck(char *helo, int connfd, int mailacc)
{
	struct heloexcept *heloex;
	char  *dup;
	struct hostent *h;
	int i;
	char ip[40];

	dup = strdup(helo);
	SLIST_FOREACH(heloex, &heloexcepthead, next) {
		if(!strcmp(heloex->helo, helo)) {
			free(dup);
			syslog(LOG_INFO, "HELO check skipped for %s", helo);
			return 0;
		}
	}

	h = gethostbyname(helo);	
	if(h == NULL) {
		syslog(LOG_INFO, "HELO check failed, host does not exist in DNS");
		globalcnt.helorejcnt++;
		updateglobalcnt();
		write(connfd,"quit\r\n", 6);
		shutdown(connfd, SHUT_WR);
		close(connfd);
		shutdown(mailacc, SHUT_WR);
		close(mailacc);
		return HELOREJECT;
	}
	for(i = 0; h->h_addr_list[i] != NULL; i++) {
		strncpy(ip, inet_ntoa(*(struct in_addr *)
					h->h_addr_list[i]), sizeof(ip));
		if(!matchhelo(ip)) {
			syslog(LOG_INFO, "HELO check passed");
			return 0;
		}
	}
	globalcnt.helorejcnt++;
	write(connfd,"quit\r\n", 6);
	shutdown(connfd, SHUT_WR);
	close(connfd);
	shutdown(mailacc, SHUT_WR);
	close(mailacc);
	syslog(LOG_INFO, "HELO check failed, DNS IP does not match origin IP");
	return HELOREJECT;

}

	int
sendercheck(char *sender) 
{
	struct bannedsenderids *tmp;
	regex_t regbuf;
	char *pat;

	syslog(LOG_INFO, "Doing a sender check");

	SLIST_FOREACH(tmp, &bannedsendershead, next) {
		pat = tmp->mailid;
		if (regcomp(&regbuf, pat, REG_ICASE | REG_EXTENDED) != 0) {
			unlink(tmpmailname);
			exit (1);
		}
		if (regexec(&regbuf, sender, 0, NULL, 0) == 0) {
			/* XXX Drop mail since pattern is matched */
			dropmail = 1;
			reason = BLOCKED_SENDER;
			globalcnt.bannedsendercnt++;
			updateglobalcnt();
			syslog(LOG_INFO, "Mail dropped due to BLOCKED_SENDER match");
			return DROPPED;
		}
	}

	syslog(LOG_INFO, "Sender check passed!");

	return 0;
}

	int
recipcheck(char *recip)
{
	regex_t regbuf;
	char *pat;
	struct bannedrecipids *tmp;

	SLIST_FOREACH(tmp, &bannedreciphead, next) {
		pat = tmp->mailid;
		if (regcomp(&regbuf, pat, REG_ICASE | REG_EXTENDED) != 0) {
			unlink(tmpmailname);
			exit (1);
		}
		if (regexec(&regbuf, recip, 0, NULL, 0) == 0) {
			/* XXX Drop mail since pattern is matched */
			dropmail = 1;
			reason = BLOCKED_RECIP;
			globalcnt.bannedrecipcnt++;
			updateglobalcnt();
			syslog(LOG_INFO, "Mail dropped due to BLOCKED_RECIP match");
			return DROPPED;
		}
	}
	return -1;
}

	int
mimecheck()
{
	struct bannedmime *blmime;
	struct allowedmime *almime;
	char *sep, *dup;

	dup = strdup(mimes);
	SLIST_FOREACH(blmime, &bannedmimehead, next) {
		while( (sep = strsep(&dup, ":")) ) {
			if(!strcmp(blmime->mime, sep)) {
				/* XXX Drop mail since pattern is matched */
				if(sc_parms.banattact == PASS) {
					syslog(LOG_INFO, "Banned attachment passed");
					free(dup);
					return 0;
				} else if(sc_parms.banattact == REJECT) {
					syslog(LOG_INFO, "Banned attachment rejected");
					dropmail = 1;
					reason = BLOCKED_MIME;
					globalcnt.bannedmimecnt++;
					updateglobalcnt();
					strncpy(quareason, "Banned attachment", sizeof(quareason));
					syslog(LOG_INFO, "Mail dropped due to BLOCKED_MIME match");
					free(dup);
					dropmailnotify();
					return DROPPED;
				} else if(sc_parms.banattact == QUARANTINE) {
					syslog(LOG_INFO, "Banned attachment quarantined");
					dropmail = 1;
					reason = BLOCKED_MIME;
					globalcnt.bannedmimecnt++;
					updateglobalcnt();
					insertqua = 1;
					strncpy(quareason, "Banned attachment", sizeof(quareason));
					syslog(LOG_INFO, "Mail dropped due to BLOCKED_MIME match");
					free(dup);
					dropmailnotify();
					return DROPPED;

				}
			}
		}
	}

	SLIST_FOREACH(almime, &allowedmimehead, next) {
		while( (sep = strsep(&dup, ":")) ) {
			if(!strcmp(almime->mime, sep)) {
				/* XXX Drop mail since pattern is matched */
				syslog(LOG_INFO, "Attach MIME is allowed");
				free(dup);
				return 0;
			}
		}
	}
	free(dup);
	return -1;

}

	int
surblcheck(char *tmpmailname)
{
	int ret, tmpfd;
	FILE *sfp = NULL;
	char tmpbuf[8192], tmpurls[1024];

	snprintf(tmpurls, 1024, "/tmp/url.XXXXXXXXXX"); 
	syslog(LOG_INFO, 
			"Opening the tmp URL file for SURBL...");
	if ((tmpfd = mkstemp(tmpurls)) == -1 ||
			(sfp = fdopen(tmpfd,
				      "w+")) == NULL) {

		syslog(LOG_ERR, " I get URL write fd as -1");
		if (tmpfd != -1) {
			unlink(tmpurls);
			close(tmpfd);
		}
		warn("%s", tmpurls);
		perror("open(2)");
		unlink(tmpmailname);
		exit(128);
	}
	chmod(tmpurls, S_IRUSR | S_IRGRP | S_IROTH);

	syslog(LOG_INFO, "Opened /tmp URLs mail file %s", tmpurls);


	snprintf(tmpbuf, sizeof(tmpbuf), 
			"/usr/bin/grep -o \"http://*.*\" %s | cut -c8- > %s",
			tmpmailname, tmpurls);
	ret = system(tmpbuf);
	ret >>= 8;
	/* Do a surbl lookup if URLs found in mail body */
	if(ret != 0) {
		unlink(tmpurls);
		return 0;
	} else {
		syslog(LOG_INFO, "Performing SURBL check... against %s", tmpmailname);

		snprintf(tmpbuf, sizeof(tmpbuf), 
				"/usr/local/bin/surblhost -r - < %s", tmpurls);
		ret = system(tmpbuf);
		ret >>= 8;
		unlink(tmpurls);
		switch(ret) {
			case 0:
				syslog(LOG_INFO, "SURBL check passed, good");
				return 0;
			case 1:
				syslog(LOG_INFO, "SURBL check failed, net down?");
				return 0;
			case 2:
				syslog(LOG_INFO, "SURBL returned blacklist, mail dropped");
				globalcnt.surblrejcnt++;
				globalcnt.spamcnt++;
				updateglobalcnt();
				dropmail = 1;
				return SURBLREJECT;
			default:
				syslog(LOG_INFO, "SURBL return not recognized");
				return 0;

		}
	}

}

	int
mail_att_process(void)
{
	char tmpbuf[8192], buf[1024];
	FILE *fp;
	int lineno = 0 ;

	/* reformime */
	snprintf(buf, sizeof(buf), 
			"/usr/bin/reformime -i < %s"
			" | egrep 'filename|content-type' |cut -d: -f2", tmpmailname);
	fp = popen(buf, "r");
	bzero(mailattr, sizeof(mailattr));
	bzero(tmpbuf, sizeof(tmpbuf));
	while(fgets(buf, sizeof(buf), fp)) {
		buf[strcspn(buf, "\n")] = 0;
		if(strchr(buf, '/') == NULL) {
			lineno++;
			strncat(tmpbuf, buf + 1, sizeof(tmpbuf));
			strncat(tmpbuf, ":", sizeof(tmpbuf));
		} else {
			strncat(mimes, buf + 1, sizeof(mimes));
			strncat(mimes, ":", sizeof(mimes));
		}
	}
	fclose(fp);
	snprintf(buf, sizeof(buf), ",att:%d:", lineno);
	snprintf(mailattr, sizeof(mailattr), "mime:");
	strncat(mailattr, mimes, sizeof(mailattr));
	strncat(mailattr, buf, sizeof(mailattr));
	strncat(mailattr, tmpbuf, sizeof(mailattr));
	syslog(LOG_INFO, "Attachment list, [%s] ", mailattr);

	mimecheck();

	return 0;
}

	int
match_addr(char *net, u_int32_t testip)
{
	u_int32_t nw, mask, nwnet, testnet;
	char *p, *cp;
	struct in_addr nwip ;
	int maskbits;

	cp = strdup(net);
	p = strchr(cp, '/');
	*p = 0;
	maskbits = strtol(p + 1, NULL, 10);
	inet_aton(cp, &nwip);
	free(cp);

	/* At this point we have nwip and maskbits parsed */

	nw = nwip.s_addr;
	mask = ~(0xffffffff << maskbits);
	/* Now we have mask in proper form */

	nwnet = nw & mask;
	testnet = testip & mask;

	if(testnet == nwnet) {
		syslog(LOG_INFO, "The IP matches netscheck");
		return 0;
	} else {
		syslog(LOG_INFO,"The IP DOES not match netscheck");
		return 1;
	}

	free(cp);

}

/* XXX code that inserts data into Postgres DB */

static void
exit_nicely(PGconn *conn)
{
    PQfinish(conn);
    exit(1);
}

int insert_quadb(int size)
{
	const char *conninfo;
	PGconn     *conn;
	PGresult   *res;
	char insert[8192], tmp[1024];
	time_t now;

	time(&now);

	memset(insert, 0, sizeof(insert));
	strncat(insert,  "insert into quamail values(DEFAULT,'", sizeof(insert));
	strncat(insert, quafile, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, headers, sizeof(insert));
	strncat(insert, "',", sizeof(insert));
	snprintf(tmp, 1024,"%d", size);
	strncat(insert, tmp, sizeof(insert));
	strncat(insert, ",'", sizeof(insert));
	strncat(insert, subject, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, date,  sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, fromid, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, toid, sizeof(insert));
	strncat(insert, "',", sizeof(insert));
	snprintf(tmp, 1024,"%d", (int)now);
	strncat(insert, tmp, sizeof(insert));
	strncat(insert, ",'", sizeof(insert));
	strncat(insert, mailattr, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, envip, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, quareason, sizeof(insert));
	strncat(insert, "');", sizeof(insert));

	syslog(LOG_INFO, "Query is [%s]", insert);

	conninfo = "dbname = postgres user=postgres password=panache";

	syslog(LOG_INFO, "Opening the Quarantine DB...");
	/* Make a connection to the database */
	conn = PQconnectdb(conninfo);

	/* Check to see that the backend connection was successfully made */
	if (PQstatus(conn) != CONNECTION_OK)
	{
		fprintf(stderr, "Connection to database failed: %s",
				PQerrorMessage(conn));
		exit_nicely(conn);
	}

	syslog(LOG_INFO, "Inserting into Quarantine DB...");
	/* Start a transaction block */
	res = PQexec(conn, insert);
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		syslog(LOG_ERR, "INSERT command failed: %s", PQerrorMessage(conn));
		PQclear(res);
		exit_nicely(conn);
	}

	/*
	 * Should PQclear PGresult whenever it is no longer needed to avoid memory
	 * leaks
	 */
	PQclear(res);

	/* close the connection to the database and cleanup */
	PQfinish(conn);


	syslog(LOG_INFO, "Query executed in SQL to insert quarantine data");
	return 0;
}

int insert_maildb(int size)
{
	const char *conninfo;
	PGconn     *conn;
	PGresult   *res;

	char insert[8192], tmp[1024];
	time_t now;

	time(&now);

	memset(insert, 0, sizeof(insert));
	strncat(insert,  "insert into mails values(DEFAULT,'", sizeof(insert));

	strncat(insert, envip, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, envfrom, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, envto, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, fromid, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, toid, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, subject, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, date, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, headers, sizeof(insert));
	strncat(insert, "',", sizeof(insert));
	snprintf(tmp, 1024,"%d", size);
	strncat(insert, tmp, sizeof(insert));
	strncat(insert, ",", sizeof(insert));
	snprintf(tmp, 1024,"%d", (int)now);
	strncat(insert, tmp, sizeof(insert));
	strncat(insert, ",'", sizeof(insert));
	strncat(insert, mailattr, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, osfp, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, helostring, sizeof(insert));
	strncat(insert, "','", sizeof(insert));
	strncat(insert, mailqid, sizeof(insert));
	strncat(insert, "');", sizeof(insert));

	syslog(LOG_INFO, "Query is [%s]", insert);

	conninfo = "dbname = postgres user=postgres password=panache";

	syslog(LOG_INFO, "Opening the Mailmeta DB...");
	/* Make a connection to the database */
	conn = PQconnectdb(conninfo);

	/* Check to see that the backend connection was successfully made */
	if (PQstatus(conn) != CONNECTION_OK)
	{
		fprintf(stderr, "Connection to database failed: %s",
				PQerrorMessage(conn));
		exit_nicely(conn);
	}

	syslog(LOG_INFO, "Inserting into Mailmeta DB...");
	/* Start a transaction block */
	res = PQexec(conn, insert);
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		syslog(LOG_ERR, "INSERT command failed: %s", PQerrorMessage(conn));
		PQclear(res);
		exit_nicely(conn);
	}

	/*
	 * Should PQclear PGresult whenever it is no longer needed to avoid memory
	 * leaks
	 */
	PQclear(res);

	/* close the connection to the database and cleanup */
	PQfinish(conn);


	syslog(LOG_INFO, "Query executed in SQL to insert metadata");
	return 0;
}

int query_user_db(int vpem_acct_id, char *mailaddr) {
	const char *conninfo;
	PGconn     *conn;
	PGresult   *res;
	char query[8192], i;

	memset(query, 0, sizeof(query));
	snprintf(query, sizeof(query), 
	   "select rssl_sender_email from receiver_selective_sender_list where rssl_vpem_id =%d; ", vpem_acct_id);


	syslog(LOG_INFO, "Query is [%s]", query);

	conninfo = "dbname = postgres user=postgres password=panache";

	syslog(LOG_INFO, "Queryring the DB...");
	/* Make a connection to the database */
	conn = PQconnectdb(conninfo);

	/* Check to see that the backend connection was successfully made */
	if (PQstatus(conn) != CONNECTION_OK)
	{
		fprintf(stderr, "Connection to database failed: %s",
				PQerrorMessage(conn));
		exit_nicely(conn);
	}

	syslog(LOG_INFO, "Querying for sender match against DB...");
	/* Start a transaction block */
	res = PQexec(conn, query);
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
	{
		syslog(LOG_ERR, "Query command failed: %s", PQerrorMessage(conn));
		PQclear(res);
		exit_nicely(conn);
	}

	for (i = 0; i < PQntuples(res); i++) 
		strncpy(mailaddr, PQgetvalue(res, i, 0),
		   sizeof(mailaddr));

	PQclear(res);
	PQfinish(conn);

	return 0;

}

/* XXX regex magic! */

enum MATCHTYPE {
	HEADER_MATCH = 1,
	BODY_MATCH,
	SUB_MATCH,
	DATE_MATCH,
	MSGID_MATCH
} MATCHTYPE;

enum RE_TYPE {
	HEADER = 1,
	BODY,
	SUBJECT,
	DATE,
	MESSAGEID,
	NOMATCH
} RE_TYPE;

	int
matchtype(void) 
{

	if(strcasestr(matchre.type,"header")) {
		regextype = HEADER;
	} else if(strcasestr(matchre.type, "body")) {
		regextype = BODY;
	} else if(strcasestr(matchre.type, "subject")) {
		regextype = SUBJECT;
	} else if(strcasestr(matchre.type, "date")) {
		regextype = DATE;
	} else if(strcasestr(matchre.type, "messageid")) {
		regextype = MESSAGEID;
	}
	return 0;
}

	int
searchfullheader(regex_t *regbuf, char *header)
{

	syslog(LOG_INFO, "Doing REGEX match on Full HEADER\n");
	if (regexec(regbuf, header, 0, NULL, 0) == 0) {
		syslog(LOG_INFO, "REGEX matches on HEADER!\n");
		return HEADER_MATCH;
	}

	syslog(LOG_INFO, "NO REGEX match on HEADER!\n");
	return NOMATCH;
}

	int
searchbody(regex_t *regbuf, int rfd)
{
	char buf[8192];
	int n;


	syslog(LOG_INFO, "Doing REGEX match on BODY\n");
	while( (n = read(rfd, buf, sizeof(buf))) ){
		if (regexec(regbuf, buf, 0, NULL, 0) == 0) {
			syslog(LOG_INFO, "REGEX matches on BODY!\n");
			return BODY_MATCH;
		}
	}
	close(rfd);
	syslog(LOG_INFO, "NO REGEX match on BODY!\n");
	return NOMATCH;
}

int searchheaderfields(regex_t *regbuf, int patcnt, char *line, int r)
{
	char *p;

	p = strchr(line, ':');
	/* : */
	p++;
	/* space */
	p++;
	/* Get rid of newline */
	line[r-2] = 0;

	syslog(LOG_INFO, "Doing REGEX match on Header fields\n");
	switch(patcnt) {
		case 0:
			if(regextype == SUBJECT) {
				if (regexec(regbuf, p, 0, NULL, 0) == 0) {
					syslog(LOG_INFO, "REGEX matches on SUBJECT!\n");
					return SUB_MATCH; 
				} else 
					return NOMATCH;
			}
			break;
		case 1:
			if(regextype == DATE) {
				if (regexec(regbuf, p, 0, NULL, 0) == 0) {
					syslog(LOG_INFO, "REGEX matches on DATE!\n");
					return DATE_MATCH;
				} else 
					return NOMATCH;

			}
			break;
		case 2:
			if(regextype == MESSAGEID) {
				if (regexec(regbuf, p, 0, NULL, 0) == 0) {
					syslog(LOG_INFO, "REGEX matches on MESSAGEID!\n");
					return MSGID_MATCH;
				} else
					return NOMATCH;
			}
			break;
		default:
			break;
	}
	return NOMATCH;
}

int 
searchmail(char *file) {
	regex_t t, regbuf;
	char *pat = NULL;
	int line_number = 0;
	char line_buffer[BUFSIZ];
	FILE *mailf;
	int stop, rfd = -1;

	if (regcomp(&regbuf, matchre.pat, REG_ICASE | REG_EXTENDED) != 0) {
		syslog(LOG_INFO,"Regex compilation issue");
		exit(1);
	}
	stop = 0;
	mailf = fopen(file, "r");
	if(mailf == NULL) {
		syslog(LOG_INFO,"Could not open file\n");
		exit(128);
	}
	memset(headers, 0, sizeof(headers));
	while(fgets(line_buffer, sizeof(line_buffer), mailf)) {
		++line_number;

		if(line_buffer[0] == '\r' && line_buffer[1] == '\n')
			stop = 1;
		if(stop == 0)
			strncat(headers, line_buffer, sizeof(headers));
		if(regextype == SUBJECT) {
			pat = researchpats[0];
			if (regcomp(&t, pat, REG_ICASE | REG_EXTENDED) != 0) {
				syslog(LOG_INFO,"Could not compile regex\n");
				exit (1);
			}
			if (regexec(&t, line_buffer, 0, NULL, 0) == 0) {
				return searchheaderfields(&regbuf, 0, line_buffer,
						strlen(line_buffer));
			} 
		} else if(regextype == DATE) {
			pat = researchpats[1];
			if (regcomp(&t, pat, REG_ICASE | REG_EXTENDED) != 0) {
				syslog(LOG_INFO,"Could not compile regex\n");
				exit (1);
			}
			if (regexec(&t, line_buffer, 0, NULL, 0) == 0) {
				return searchheaderfields(&regbuf, 1, line_buffer,
						strlen(line_buffer));
			} 
		} else if(regextype == MESSAGEID) {
			pat = researchpats[2];
			if (regcomp(&t, pat, REG_ICASE | REG_EXTENDED) != 0) {
				syslog(LOG_INFO,"Could not compile regex\n");
				exit (1);
			}
			if (regexec(&t, line_buffer, 0, NULL, 0) == 0) {
				return searchheaderfields(&regbuf, 2, line_buffer,
						strlen(line_buffer));
			} 
		}
		if(stop == 1) {
			rfd = fileno(mailf);
			break;
		}
	} 

	if(regextype == HEADER) {
		return searchfullheader(&regbuf, headers);
	} else {
		lseek(rfd, strlen(headers), SEEK_SET);
		return searchbody(&regbuf, rfd);
	}
	fclose(mailf);
}

	int 
regexcheck(void)
{
	matchtype();
	return  searchmail(tmpmailname);
}

	int
sendtomta(int connfd, char *p, int r, struct pollfd pfd, int mailacc)
{
	int w = 0, bytestowrite;
	char *t, trailer[1024];

	syslog(LOG_INFO, "Writing %d bytes to mail server", r);

	bytestowrite = r;

	t = strstr(p, ".\r\n");
	if(t && sc_parms.discset) {
		strncpy(trailer, t, sizeof(trailer));
		bytestowrite = r - strlen(t);
		syslog(LOG_INFO, "Trailer is [%s]", trailer);
	}



	do {
		w = write(connfd, p + w, bytestowrite);
		if(w == 0 || w == -1) {
			syslog(LOG_INFO, "Inside: Mail Server sock closed on write(2)");
			shutdown(connfd, SHUT_WR);
			close(connfd);
			shutdown(mailacc, SHUT_WR);
			close(mailacc);
			pfd.fd = -1;
			pfd.events = 0;
			unlink(tmpmailname);
			exit(0);
		}
		bytestowrite -= w;

	} while(bytestowrite);

	if(t && sc_parms.discset) {
		strncat(disclaim.body, "\r\n", sizeof(disclaim.body));
		strncat(disclaim.body, trailer, sizeof(disclaim.body));
		syslog(LOG_INFO, "Writing disclaimer... [%s]", disclaim.body);
		w = write(connfd, disclaim.body, strlen(disclaim.body));
		if(w == 0 || w == -1) {
			syslog(LOG_INFO, "Inside: Mail Server sock closed on write(2)");
			shutdown(connfd, SHUT_WR);
			close(connfd);
			shutdown(mailacc, SHUT_WR);
			close(mailacc);
			pfd.fd = -1;
			pfd.events = 0;
			unlink(tmpmailname);
			exit(0);
		}
		syslog(LOG_INFO, "Wrote disclaimer of %d bytes to SERVER socket", w);
	}
	return 0;
}

int save_header(int patcnt, char *line, int r) 
{
	char *p;

	p = strchr(line, ':');
	/* : */
	p++;
	/* space */
	p++;
	/* Get rid of newline */
	line[r-2] = 0;

	switch(patcnt) {
		case 0:
			strncpy(fromid, p, sizeof(fromid));
			break;
		case 1:
			strncpy(toid, p, sizeof(toid));
			break;
		case 2:
			strncpy(subject, p, sizeof(subject));
			break;
		case 3:
			strncpy(date, p, sizeof(date));
			break;
		case 4:
			strncpy(msgid, p, sizeof(msgid));
			break;
		default:
			break;
	}
	return 0;
}

int despatchmail(int mailacc, struct pollfd pfd, struct sockaddr_in clientaddr, FILE *sfp,int connfd) {
	regex_t regbuf;
	char *pat, *p;
	int line_number = 0, readfd;
	int patcnt, r = 0;
	char line_buffer[BUFSIZ];
	FILE *mailf;
	char tmpbuf[8192];
	static int stop;

	stop = 0;
	/* Read the mail body line by line and sendtomta() 
	 * until headers are exhausted. After that it is 
	 * block by block of pass thro'.
	 */
	mailf = fopen(tmpmailname, "r");
	memset(headers, 0, sizeof(headers));
	while(fgets(line_buffer, sizeof(line_buffer), mailf)) {
		++line_number;

		if(line_buffer[0] == '\r' && line_buffer[1] == '\n')
			stop = 1;
		if(stop == 0)
			strncat(headers, line_buffer, sizeof(headers));
		/* XXX figure out regex match stuff */
		for(patcnt = 0; patcnt <= 4; patcnt ++) {
			pat = searchpats[patcnt];
			if (regcomp(&regbuf, pat, REG_ICASE | REG_EXTENDED) != 0) {
				unlink(tmpmailname);
				exit (1);
			}

			if (regexec(&regbuf, line_buffer, 0, NULL, 0) == 0) {
				save_header(patcnt, line_buffer,
						strlen(line_buffer));
			} 
		}
		if(stop == 1) {
			snprintf(tmpbuf, sizeof(tmpbuf), 
					"X-From-IP: %s\r\n", inet_ntoa(clientaddr.sin_addr));
			//strncat(headers, tmpbuf, sizeof(line_buffer));
			p = headers;
			r = strlen(headers);
			sendtomta(connfd, p, r, pfd, mailacc);
			readfd = fileno(mailf);
			break;
		}
	} /* while(fgets(line_buffer, sizeof(line_buffer), mailf)) */

	syslog(LOG_INFO, "Opening the mail file %s to send to MTA...", tmpmailname);

	syslog(LOG_INFO, "Proceeding to read and send mail");
	readfd = open(tmpmailname, O_RDONLY);
	if(readfd == -1) {
		syslog(LOG_ERR, " I get mail read fd as -1 Exiting...");
		exit(128);
	}

	lseek(readfd, r, SEEK_SET);
	/* This is the code that sends the mail to the MTA block
	 * XXX  block in a loop
	 */
	while( (r = read(readfd, tmpbuf, sizeof(tmpbuf))) ) {
		syslog(LOG_INFO, "I read %d bytes from file", r);
		sendtomta(connfd, tmpbuf, r, pfd, mailacc);
	}
	sendtomta(connfd, "\r\n.\r\n", 5, pfd, mailacc);
	close(readfd);
	fclose(mailf);
	return 0;
}

int quarantinemail(void) {
	FILE  *sfp = NULL;
	regex_t regbuf;
	char *pat;
	int line_number = 0;
	int patcnt,  tmpfd = -1;
	char line_buffer[BUFSIZ];
	FILE *mailf;
	char tmpbuf[8192];
	static int stop;

	stop = 0;
	/* Read the mail body line by line and sendtomta() 
	 * until headers are exhausted. After that it is 
	 * block by block of pass thro'.
	 */
	mailf = fopen(tmpmailname, "r");
	if(mailf == NULL) {
		syslog(LOG_ERR, " I am getting a ZERO byte mail file in %s", tmpmailname);
		return -1;
	}
	memset(headers, 0, sizeof(headers));
	while(fgets(line_buffer, sizeof(line_buffer), mailf)) {
		++line_number;

		if(line_buffer[0] == '\r' && line_buffer[1] == '\n')
			stop = 1;
		if(stop == 0)
			strncat(headers, line_buffer, sizeof(headers));
		for(patcnt = 0; patcnt <= 4; patcnt ++) {
			pat = searchpats[patcnt];
			if (regcomp(&regbuf, pat, REG_ICASE | REG_EXTENDED) != 0) {
				unlink(tmpmailname);
				exit (1);
			}
			if (regexec(&regbuf, line_buffer, 0, NULL, 0) == 0) {
				save_header(patcnt, line_buffer,
						strlen(line_buffer));
			} 
		}
		if(stop == 1) {
			fclose(mailf);
			break;
		}
	} 

	snprintf(quafile, 1024, "/var/www/quamail/quamail.XXXXXXXXXX"); 
	if ((tmpfd = mkstemp(quafile)) == -1 ||
			(sfp = fdopen(tmpfd,
				      "w+")) == NULL) {

		syslog(LOG_ERR, " I get quafile write fd as -1"); 
		if (tmpfd != -1) { 
			unlink(quafile);
			close(tmpfd);
		}
		warn("%s", quafile);
		perror("open(2)");
		unlink(quafile);
		exit(128);
	}
	chmod(quafile, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR);
	close(tmpfd);

	sprintf(tmpbuf, "/bin/cp %s %s", tmpmailname, quafile);
	system(tmpbuf);
	syslog(LOG_INFO, "Copied the mail to quafile");
	//insert_quadb(mailsz);

	return 0;
}

int dropmailnotify(void) {
	/* XXX mail drop code */
	switch(reason) {

		case VIRUS_FOUND:
			if(sc_parms.notifset) {
				notify_virus_sender();
				notify_virus_recip();
			}
			syslog(LOG_INFO, "Mail dropped due to: VIRUS FOUND");
			break;
		case RAZOR_SPAM_FOUND:
			syslog(LOG_INFO, "Mail dropped due to: Spam detected by Vipul's razor");
			break;
		case REGEX_MATCH:
			syslog(LOG_INFO, "Mail dropped due to: REGEX match");
			break;
		case BMF_SPAM_FOUND:
			syslog(LOG_INFO, "Mail dropped due to: Spam detected by BMF content scanner");
			break;
		case BLOCKED_SENDER_QUARANTINE:
			if(sc_parms.notifset) {
				notify_blocked_sender();
			}
			syslog(LOG_INFO, "Mail dropped due to: BANNED QUARANTINE SENDER");
			break;
		case BLOCKED_NOT_ALLOWED_NETWORK:
		case BLOCKED_DENIED_NETWORK:
			syslog(LOG_INFO, "Mail dropped due to: DENIED NETWORK");
			break;
		case BLOCKED_RECIP:
			if(sc_parms.notifset) {
				notify_blocked_recip();
			}
			syslog(LOG_INFO, "Mail dropped due to: BANNED RECIPIENT");
			break;
		case BLOCKED_MIME:
			if(sc_parms.notifset) {
				notify_blocked_mime();
			}
			syslog(LOG_INFO, "Mail dropped due to: BANNED MIME TYPE");
			break;
		case BLOCKED_ATTACH:
			if(sc_parms.notifset) {
				notify_blocked_attach();
			}
			syslog(LOG_INFO, "Mail dropped due to: BANNED ATTACHMENT");
			break;
		case SIZE_EXCEEDED:
			if(sc_parms.notifset) {
				notify_size_exceeded();
			}
			syslog(LOG_INFO, "Mail dropped due to: SIZE EXCEEDED");
		default:
			syslog(LOG_INFO, "Mail dropped due to unknown cause");
			break;
	}

	if(insertqua == 1) 
		quarantinemail();

	return DROPPED;
}

int checkeom(int tmpfd, char *buf, char *residue, int r)
{
	struct stat sb;
	char chk[8192];

	write(tmpfd, buf, r);

	strncpy(chk, residue, sizeof(chk));
	strncat(chk, buf, strlen(buf));

	if((strstr(chk, "\r\n.\r\n"))) {
		syslog(LOG_INFO, "Found DATA end");
		fstat(tmpfd, &sb);
		mailsz = sb.st_size;
		truncate(tmpmailname, mailsz - 3);
		mailsz -= 3;
		close(tmpfd);
		syslog(LOG_INFO, "Wrote mail to a file size %ld", mailsz);
		return 0;
	} else {
		syslog(LOG_INFO, "Returning partial write after writing %d bytes", r);
		return 1;
	}
	return 1;
}

/* XXX code that does the real work of processing mail */
	int
process_mail(int mailacc, struct pollfd pfd, struct p0f_response *p0fr, struct sockaddr_in clientaddr, int connfd, char *buf, int r)
{
	FILE  *sfp = NULL;
	char tmpbuf[8192], residue[8192];
	static int f = 0, tmpfd = -1;
	char  *ln, *sep, *slashr, *sv;
	int  ret = -1;
	int virusfound = 0, spamfound = 0;

	if(f == 0) {
		snprintf(tmpmailname, 1024, "/tmp/mail.XXXXXX"); 
		syslog(LOG_INFO, 
				"Opening the mail file to write to send to MTA...");
		if ((tmpfd = mkstemp(tmpmailname)) == -1 ||
				(sfp = fdopen(tmpfd,
					      "w+")) == NULL) {

			syslog(LOG_ERR, " I get mail write fd as -1");
			if (tmpfd != -1) {
				unlink(tmpmailname);
				close(tmpfd);
			}
			warn("%s", tmpmailname);
			perror("open(2)");
			exit(128);
		}
		chmod(tmpmailname, S_IRUSR | S_IRGRP | S_IROTH);

		syslog(LOG_INFO, "Opened /tmp mail file %s to write", tmpmailname);
		f = 1;
	}


	ln = strdup(buf);
	sv = ln;
	while( (sep = strsep(&ln, "\n")) ) {
		if(*sep == '\r' && strlen(sep) == 1) {
			break;
		}
		slashr = strchr(sep, '\r');
		if(slashr) 
			*slashr = 0;
		if(!memcmp(sep, "From:", 5) || !memcmp(sep, "Date:", 5) ||
				!memcmp(sep, "Subject:", 8) || 
				!memcmp(sep, "To:", 3) ||
				!memcmp(sep, "Received:", 9) )
			syslog(LOG_INFO, "--> %s", sep);
	}
	free(sv);

	/* Check whether mail body has ended */
	if(r > 5)
		strncpy(residue, buf+r-5, sizeof(residue));	
	else 
		residue[0] = 0;
	f = checkeom(tmpfd, buf, residue, r);
	if(f == 1)
		return PARTIALWRITE;

	if(mailsz > maxmailsz) {
		dropmail = 1;
		reason = SIZE_EXCEEDED;
		globalcnt.mailszcnt++;
		updateglobalcnt();
		syslog(LOG_INFO, "Mail dropped due to MAILSIZE_EXCEEDED match");
		dropmailnotify();
		return DROPPED;
	}

	syslog(LOG_INFO, "About to do spam check");

	syslog(LOG_INFO, "dropmail = %d", dropmail);

	if(sc_parms.regexenable) {
		ret = regexcheck();

		if(ret == 6) {
			syslog(LOG_INFO,"No REGEX match!\n");
			if(matchre.flag == 0) {
				dropmail = 1;
				reason = REGEX_MATCH;
				globalcnt.matchrecnt++;
				updateglobalcnt();
				syslog(LOG_INFO, "Mail dropped due to NO REGEX match");
				dropmailnotify();
				return DROPPED;

			}
		} else {
			syslog(LOG_INFO,"REGEX matches!\n");
			if(matchre.flag) {
				dropmail = 1;
				reason = REGEX_MATCH;
				globalcnt.matchrecnt++;
				updateglobalcnt();
				syslog(LOG_INFO, "Mail dropped due to REGEX match");
				dropmailnotify();
				return DROPPED;

			}
		}
	}

	mail_att_process();

	if(sc_parms.virusenable) {
		syslog(LOG_INFO, "ClamAV scan...");
		snprintf(tmpbuf, sizeof(tmpbuf), "/usr/bin/clamdscan --quiet %s", tmpmailname);
		ret = system(tmpbuf);
		ret >>= 8;
		syslog(LOG_INFO, "ClamAV scan returns %d", ret);
		if(ret == 1) {
			/* Virus detected in body,
			 * Notify both the sender of the
			 * virus and the recipient about it 
			 */
			virusfound = 1;
		}
		if(virusfound == 1) {
			syslog(LOG_INFO, "ClamAV scan returned VIRUS FOUND");
			globalcnt.viruscnt++;
			updateglobalcnt();
			switch(sc_parms.virusact) {
				case PASS: /* Pass */
					syslog(LOG_INFO, "Virus passed");
					break;
				case QUARANTINE: /* Quarantine */
					syslog(LOG_INFO, "Virus Quarantined");
					insertqua = 1;
					strncpy(quareason, "Virus", sizeof(quareason));
					dropmail = 1;
					break;
				case REJECT: /* Reject */
					syslog(LOG_INFO, "Virus Rejected");
					dropmail = 1;
					break;

			}
			if(dropmail == 1) {
				reason = VIRUS_FOUND;
				dropmailnotify();
				return DROPPED;
			}

		}
	}

	//surblcheck(tmpmailname);

	if(sc_parms.spamenable) { /* if set in sc.conf file */
		syslog(LOG_INFO, "Razor scan...");
		/* XXX Drop the mail if it is spam */
		snprintf(tmpbuf, 
				sizeof(tmpbuf),
				"/usr/bin/razor-check %s >/dev/null", 
				tmpmailname);
		ret = system(tmpbuf);
		ret >>= 8;
		if(ret == 0) {
			spamfound = 1;
		} 
		if(spamfound == 1) {
			syslog(LOG_INFO, "Razor scan returned SPAM FOUND");
			switch(sc_parms.spamact) {
				case PASS: /* Pass */
					syslog(LOG_INFO, "Spam passed");
					break;
				case QUARANTINE: /* Quarantine */
					syslog(LOG_INFO, "Spam Quarantined");
					insertqua = 1;
					strncpy(quareason, "Spam", sizeof(quareason));
					dropmail = 1;
					break;
				case REJECT: /* Reject */
					syslog(LOG_INFO, "Spam Rejected");
					dropmail = 1;
					break;

			}
			if(dropmail) {
				globalcnt.razorrejcnt++;
				globalcnt.spamcnt++;
				updateglobalcnt();
				reason = RAZOR_SPAM_FOUND;
				dropmailnotify();
				return DROPPED;
			}

		}

		/* XXX Drop the mail if it is spam */

		syslog(LOG_INFO, "BMF scan... on %s", tmpmailname);
		snprintf(tmpbuf, 
				sizeof(tmpbuf),
				"/usr/bin/bmf -p -i %s",
				tmpmailname);
		ret = system(tmpbuf);
		ret >>= 8;
		if(ret != 0) {
			spamfound = 1;
		} 

		if(spamfound == 1) {
			syslog(LOG_INFO, "Razor scan returned SPAM FOUND");
			switch(sc_parms.spamact) {
				case PASS: /* Pass */
					syslog(LOG_INFO, "Spam passed");
					break;
				case QUARANTINE: /* Quarantine */
					syslog(LOG_INFO, "Spam Quarantined");
					insertqua = 1;
					strncpy(quareason, "Spam", sizeof(quareason));
					dropmail = 1;
					break;
				case REJECT: /* Reject */
					syslog(LOG_INFO, "Spam Rejected");
					dropmail = 1;
					break;

			}
			if(dropmail) {
				globalcnt.razorrejcnt++;
				globalcnt.spamcnt++;
				updateglobalcnt();
				reason = RAZOR_SPAM_FOUND;
				dropmailnotify();
				return DROPPED;
			}

		}
	} /* if(spamenable) */

	despatchmail(mailacc,pfd,clientaddr, sfp, connfd);
	globalcnt.goodmailcnt++;
	updateglobalcnt();
	syslog(LOG_INFO, "Despatched mail after spam checks");
	return 0;
}

/* Do update of global counters from child */
	int
doupdateglobcnt(int fd, char *buf)
{

	struct globalcnt *gl;
	gl = (struct globalcnt *)buf;

	if(gl->numattcnt != 0) 
		globalcnt.numattcnt = gl->numattcnt;
	if(gl->matchrecnt != 0) 
		globalcnt.matchrecnt = gl->matchrecnt;
	if(gl->viruscnt != 0)
		globalcnt.viruscnt = gl->viruscnt;
	if(gl->spamcnt != 0)
		globalcnt.spamcnt = gl->spamcnt;
	if(gl->bannednetcnt != 0)
		globalcnt.bannednetcnt = gl->bannednetcnt;
	if(gl->bannedsendercnt != 0)
		globalcnt.bannedsendercnt = gl->bannedsendercnt;
	if(gl->bannedrecipcnt != 0)
		globalcnt.bannedrecipcnt = gl->bannedrecipcnt;
	if(gl->bannedattcnt != 0)
		globalcnt.bannedattcnt = gl->bannedattcnt;
	if(gl->rfcrejcnt != 0)
		globalcnt.rfcrejcnt = gl->rfcrejcnt;
	if(gl->fqdnrejcnt != 0)
		globalcnt.fqdnrejcnt = gl->fqdnrejcnt;
	if(gl->dkimrejcnt != 0)
		globalcnt.dkimrejcnt = gl->dkimrejcnt;
	if(gl->helorejcnt != 0)
		globalcnt.helorejcnt = gl->helorejcnt;
	if(gl->surblrejcnt != 0)
		globalcnt.surblrejcnt = gl->surblrejcnt;
	if(gl->razorrejcnt != 0)
		globalcnt.razorrejcnt = gl->razorrejcnt;
	if(gl->spfrejcnt != 0)
		globalcnt.spfrejcnt = gl->spfrejcnt;
	if(gl->goodmailcnt != 0)
		globalcnt.goodmailcnt = gl->goodmailcnt;
	if(gl->mailszcnt != 0)
		globalcnt.mailszcnt = gl->mailszcnt;

	close(fd);
	return 0;

}

/* XXX code that processes the commands on UNIX socket */  
	int
reactunix(int fd, char *buf, int n)
{
	char *cmd, cmdswitch[8192];

	cmd = strchr(buf, '\n');
	strncpy(cmdswitch, buf, cmd - buf + 1);
	syslog(LOG_INFO, "[%s]", cmdswitch);

	if(!strcmp(cmdswitch, "DUMPSTATS")) {
		syslog(LOG_INFO, "processing DUMPSTATS...");
		dumpstats(fd);
	} else {
		syslog(LOG_INFO, "Unrecognized command from UNIX socket in reactunix()");
	}
	close(fd);
	return 0;
}

int
start_mail_relay(char *mail_ip, u_int16_t mail_port)
{
	int status;
	int  serversock;
	char buf[8192];
	char *p2, *sep, *slashr;
	struct sockaddr_in mserver, clientaddr;
	int retval, r, w,  pid, off;
	struct sockaddr_in  tmailsrv;
	int  ret, connfd;
	socklen_t l, t;
	struct p0f_response p0fr;
	int  n, unixacc = -1, globacc, mailacc = -1;
	struct pollfd pfd[2], topfd[3];
	int  writenext = 0, done;
	socklen_t on = 1;
	char *mark, *p, *p1, *upto;
	int unixsock,  globsock, len;
	struct sockaddr_un local, remote;
	char unixcmd[8192], tmpbuf[1024];


	/* Initialize disclaimer */
	syslog(LOG_INFO, "Starting mail relay function...");

	if ((unixsock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		syslog(LOG_ERR, "Could not open UNIX domain socket %s",
				SOCK_PATH);
		exit(1);
	}
	local.sun_family = AF_UNIX;
	strncpy(local.sun_path, SOCK_PATH, sizeof(local.sun_path));
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

	/* This socket is for updating global counters */

	if ((globsock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		syslog(LOG_ERR, "Could not open GLOBALCNT UNIX domain socket %s",
				SOCK_PATH);
		exit(1);
	}
	local.sun_family = AF_UNIX;
	strncpy(local.sun_path, GLOB_PATH, sizeof(local.sun_path));
	unlink(local.sun_path);
	len = sizeof(struct sockaddr_un);
	if (bind(globsock, (struct sockaddr *)&local, len) == -1) {
		perror("bind UNIX socket");
		syslog(LOG_ERR, "Could not bind GLOBALCNT UNIX domain socket %s",
				SOCK_PATH);
		exit(1);
	}
	chmod(SOCK_PATH, 0666);
	if (listen(globsock, 5) == -1) {
		perror("listen");
		syslog(LOG_ERR, 
				"Could not listen on GLOBALCNT UNIX domain socket %s", SOCK_PATH);
		exit(1);
	}


	/* Remote MTA address */
	tmailsrv.sin_addr.s_addr = inet_addr(mail_ip);
	tmailsrv.sin_family = AF_INET;
	tmailsrv.sin_port = htons(mail_port);
	l = sizeof(tmailsrv);

	/* Proxy address */
	mserver.sin_addr.s_addr = htonl(INADDR_ANY);
	mserver.sin_family = AF_INET;
	mserver.sin_port = htons(7000);

	serversock = socket(PF_INET, SOCK_STREAM, 0);
	if(serversock == -1) {
		perror("socket");
		syslog(LOG_ERR, "Could not open server socket ...exiting");
		exit(128);
	}
	retval = bind(serversock, (struct sockaddr *)&mserver, l);
	if(retval == -1) {
		perror("bind(2) on TCP 7000...");
		syslog(LOG_ERR, "Could not bind listening socket at port 7000 ...exiting");
		exit(128);
	}
	setsockopt(serversock, SOL_SOCKET, SO_REUSEADDR, &on, 1);
	listen(serversock, 1024);

	topfd[0].fd = unixsock;
	topfd[0].events = POLLIN;

	topfd[1].fd = serversock;
	topfd[1].events = POLLIN;

	topfd[2].fd = globsock;
	topfd[2].events = POLLIN;


POLLBEGIN:

	for(;;) {
		tlsmail = 0;

		syslog(LOG_INFO, "Listening for new mail connections");
		/* Doing a poll with infinite timeout for read... */
		retval = poll(topfd, 3, -1);

		if(retval == -1 || retval == 0) {
			if(errno == EINTR)
				goto POLLBEGIN ;
			syslog(LOG_ERR, "Outside poll failure: Exiting"
					" parent with retval %d", retval);
			/*  This will exit the parent... XXX dangerous*/
			exit(0);
		}

		/* XXX Config UNIX socket */
		if(topfd[0].revents & POLLIN) {
			t = sizeof(remote);
			if ((unixacc = accept(topfd[0].fd , (struct sockaddr *)&remote, &t)) == -1) {
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
				strncat(unixcmd + off, buf, sizeof(unixcmd));
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

		/* XXX Globalcnt UNIX socket */
		if(topfd[2].revents & POLLIN) {
			t = sizeof(remote);
			if ((globacc = accept(topfd[2].fd , (struct sockaddr *)&remote, &t)) == -1) {
				perror("UNIX accept");
				exit(1);
			}

			bzero(unixcmd, sizeof(unixcmd));
			n = recv(globacc, buf, sizeof(buf), 0);
			doupdateglobcnt(unixacc, buf);
			close(globacc);
			continue;
		}


		/* XXX serversock This handles the mail proxying */
		if(topfd[1].revents & POLLIN) {
			mailacc  = accept(serversock, 
					(struct sockaddr *)&clientaddr, &l);
			if(mailacc == -1) {
				syslog(LOG_ERR, "TCP accept failed");
				perror("accept");
			}
			syslog(LOG_INFO, "New connection from %s:%d", 
					inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));

			writenext = 0;
			strncpy(envip, inet_ntoa(clientaddr.sin_addr), sizeof(envip));

			globalcnt.totalmailcnt++;
			/* XXX Check whether we can receive mail from this IP */


			pid = fork();
			if(pid == -1) {
				perror("fork()");
				syslog(LOG_ERR, "Fork() failed, very bad");
			}    
			if(pid != 0) { /* Parent process */
				close(mailacc);
				waitpid(-1, &status, WNOHANG);
				continue;
				/* XXX Go back to Outside poll(2) */
			} else { /* Child process of fork() handle mail
				  * proxying in a concurrent way */

				/* Do OS fingerprint at first connection establishment phase */

				/* ret = ournatip_query(&clientaddr);
				if(ret == 0)
				
					p0fosfp(&p0fr, clientaddr.sin_addr.s_addr, 
							ntohs(clientaddr.sin_port),
							inet_addr(ourlocal),
							25);
				*/

				connfd = socket(PF_INET, SOCK_STREAM, 0);
				if(connfd == -1) {
					perror("socket");
				}

				retval = connect(connfd, (struct sockaddr *)&tmailsrv, l);
				if(retval == -1) {
					perror("connect(2)");
					syslog(LOG_ERR, "Could not connect to target mail server");
					exit(128);
				}

				syslog(LOG_INFO, "Connected to target mail server\n");

				pfd[0].fd = mailacc;
				pfd[0].events = POLLIN;

				pfd[1].fd = connfd;
				pfd[1].events = POLLIN;
				signal(SIGCHLD, waitforkidandkill);

				for(;;) {
					/* Doing a poll with infinite timeout for read... */
					retval = poll(pfd, 2, -1);

					if(retval == -1 || retval == 0) {
						perror("poll(2)");
						syslog(LOG_ERR, "Inside poll failure: Exiting child");
						/*  Only exit for Child XXX */
						exit(0);
					}

					/* XXX connfd from MTA */
					if(pfd[1].revents & POLLIN) {
						r = read(connfd, buf, sizeof(buf));
						buf[r] = 0;
						if(r == 0 || r == -1) {
							syslog(LOG_INFO, "Target Mail Server sock closed on read(2)");
							shutdown(connfd, SHUT_WR);
							close(connfd);
							shutdown(mailacc, SHUT_WR);
							close(mailacc);

							pfd[1].fd = -1;
							pfd[1].events = 0;
							if(tlsmail) {
								;//insert_maildb(mailsz);
							}
							unlink(tmpmailname);
							
							exit(0);
						}
						p = strdup(buf);
						while( (sep = strsep(&p, "\r\n")) ) {
							char *t;
							slashr = strchr(sep, '\r');
							if(slashr) 
								*slashr = 0;
							if(isalnum(sep[0]))
								syslog(LOG_INFO, "<-- %s", sep);
							if( (t = strstr(sep, "queued")) ) {
								strncpy(mailqid,
										t + 10, sizeof(mailqid));
								//insert_maildb(mailsz);
								unlink(tmpmailname);
							}	
						}
						free(p);

						w = write(mailacc, buf, r);
						if(w == 0 || w == -1) {
							syslog(LOG_INFO, "Mail Client sock closed on write(2)");
							shutdown(mailacc, SHUT_WR);
							close(mailacc);
							shutdown(connfd, SHUT_WR);
							close(connfd);
							pfd[0].fd = -1;
							pfd[0].events = 0;
							if(tlsmail) {
								//insert_maildb(mailsz);
							}
							unlink(tmpmailname);
							exit(0);
						}
					}
					/* XXX mailacc MTA client */
					if(pfd[0].revents & POLLIN) {
						r = read(mailacc, buf, sizeof(buf));
						buf[r] = 0;
						if(r == 0 || r == -1) {

							syslog(LOG_INFO,
									"Mail Client sock closed on read(2)");
							shutdown(mailacc, SHUT_WR);
							close(mailacc);
							shutdown(connfd, SHUT_WR);
							close(connfd);
							pfd[0].fd = -1;
							pfd[0].events = 0;
							unlink(tmpmailname);
							exit(0);
						}
						syslog(LOG_INFO, "Read %d bytes from Mail client\n", r);
						if(writenext == 0) {
							p = strdup(buf);
							while( (sep = strsep(&p, "\r\n")) ){
								slashr = strchr(sep, '\r');
								if(slashr) 
									*slashr = 0;
								if(isalnum(sep[0]) && !tlsmail)
									syslog(LOG_INFO, "--> : %s", sep);
							}
							free(p);
						} else {
							/* The main mail analysis happens here XXX */ 
							dropmail = 0, insertqua = 0;
							ret = process_mail(mailacc, 
									pfd[0], &p0fr, clientaddr,
									connfd, buf, r);
							if(ret == DROPPED) {
								syslog(LOG_INFO,
										"I am now going to DROPMAIL");
								goto DROPMAIL;
							} 
							if(ret == 0) 
								writenext = 0;
							continue;
						} 

						/* This part executes before we start writing mail body */
						if( (p1 = strcasestr(buf,
										"ehlo")) || (p1 = strcasestr(buf, "helo")) ) { 
							mark = strchr(p1, ' ');
							upto = strchr(p1, '\r');
							if(upto == NULL)	
								syslog(LOG_ERR, "NULL pointer");
							if(upto)
								strncpy(helostring, mark + 1, upto -mark);
							syslog(LOG_INFO, "HELO string is [%s]\n", 
									helostring);
							if(sc_parms.reqfqdn) {
								ret =  fqdncheck(helostring);
								if(ret == FQDNREJECT) {
									w = write(mailacc,"551 Sorry we accept only FQDN in HELO/EHLO", 16); 
									shutdown(connfd, SHUT_WR);
									close(connfd);
									shutdown(mailacc, SHUT_WR);
									close(mailacc);
									pfd[0].fd = -1;
									pfd[0].events = 0;
									unlink(tmpmailname);
									exit(128);
								}
							}

							if(sc_parms.helocheck) {
								ret = helocheck(helostring, connfd, mailacc);
								if(ret == HELOREJECT) {
									w = write(mailacc, "551 Invalid HELO", 16);
									shutdown(connfd, SHUT_WR);
									close(connfd);
									shutdown(mailacc, SHUT_WR);
									close(mailacc);
									pfd[0].fd = -1;
									pfd[0].events = 0;
									unlink(tmpmailname);
									exit(128);
								}
							}

						} 

						if( (p1 = strcasestr(buf, "starttls")) ){
							tlsmail = 1;
							syslog(LOG_INFO, "[ENCRYPTED] so not logging SMTP handshake");
						}
						if( (p1 = strcasestr(buf, "mail from")) ){
							syslog(LOG_INFO, "Checking for ENV mail from");
							mark = strchr(p1, ':');
							upto = strchr(p1 , '>');
							if(upto == NULL)
								syslog(LOG_ERR, "NULL pointer");
							if(upto) {
								strncpy(envfrom, 
										mark + 1, upto - mark);
								envfrom[upto-mark] = 0;
							}
							if(envfrom[0] == 0) {
								syslog(LOG_INFO, "NULL ENVFROM exiting");
								shutdown(connfd, SHUT_WR);
								close(connfd);
								shutdown(mailacc, SHUT_WR);
								close(mailacc);
								pfd[0].fd = -1;
								pfd[0].events = 0;
								exit(128);

							}
							syslog(LOG_INFO, "ENVFROM is [%s]\n", 
									envfrom);

							syslog(LOG_INFO, "Checking for RFC 2821 compatibility");
							if(sc_parms.rfccomp) {
								ret = rfccheck(envfrom);
								if(ret == RFCREJECT) {
									w = write(mailacc, 
											"551 SMTP RFC 2821 check failed", 16);
									shutdown(connfd, SHUT_WR);
									close(connfd);
									shutdown(mailacc, SHUT_WR);
									close(mailacc);
									pfd[0].fd = -1;
									pfd[0].events = 0;
									exit(128);
								}
							}
						} 

						if((p1 = strcasestr(buf, "rcpt to"))) {
							syslog(LOG_INFO, "Checking for ENV rcpt to");
							mark = strchr(p1, ':');
							upto = strchr(p1, '>');
							if(upto) {
								strncpy(envto, 
										mark + 1, upto - mark);
								envto[upto-mark] = 0;
							}
							syslog(LOG_INFO, "ENVTO is [%s]\n", envto);
							ret = recipcheck(envto);
							if(ret == DROPPED)
								goto DROPMAIL;
						} 
						if(strcasestr(buf, "data\r\n")) {
							writenext = 1;
						} 

						w = write(connfd, buf, r);
						if(w == 0 || w == -1) {
							syslog(LOG_INFO, "Outside: Mail Server sock closed on write(2)");
							shutdown(connfd, SHUT_WR);
							close(connfd);
							shutdown(mailacc, SHUT_WR);
							close(mailacc);
							pfd[0].fd = -1;
							pfd[0].events = 0;
							unlink(tmpmailname);
							exit(0);
						}
					}/* if(pfd[0].revents & POLLIN)  */
				} /* Inner for() for poll(2) for mail
				   * proxying between client and 
				   * accepted socket in server 
				   */
DROPMAIL:
                                        syslog(LOG_INFO, 
"I am dropping the mail after sending 554 to remote mail client...");
                                        strncpy(tmpbuf, "554 5.2.1 Error: E-mail refused", sizeof(tmpbuf));
                                        write(connfd,tmpbuf, strlen(tmpbuf));
                                        shutdown(connfd, SHUT_WR);
                                        close(connfd);
                                        shutdown(mailacc, SHUT_WR);
                                        close(mailacc);
                                        unlink(tmpmailname);
                                        exit(0);


			} /* child */
		}/* if(topfd[1].revents & POLLIN)  */

		syslog(LOG_INFO, "parent: Returning to Outside poll...");
	} /* Out for(;;) loop for mailserver and UNIX socket */

	return 0;
}

int
main(int argc, char **argv)
{
	pid_t pid;
	struct itimerval intvl;
	if(argc <= 2) {
		printf("Please furnish the mail server IP address"  
		" and port to start relay\n");
		exit(128);
	}
	openlog("smtprelay",  LOG_PID , LOG_LOCAL3);
	syslog(LOG_INFO, "The mail server IP is %s and port is %ld\n", argv[1],
	   strtol(argv[2], NULL, 10));
	syslog(LOG_INFO, "Starting SMTP relay process...");

	resetcounters(1);
	
	signal(SIGCHLD, waitforkidandkill);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, configparse);
	signal(SIGALRM, resetcounters);

	/* Once a day clear all stats counters */
	intvl.it_interval.tv_sec = 86400;
	intvl.it_interval.tv_usec = 0;

	intvl.it_value.tv_sec = 86400;
	intvl.it_value.tv_usec = 0;

	setitimer(ITIMER_REAL, &intvl, NULL);

	syslog(LOG_INFO, "Doing Config parsing ");
	configparse(1);
	syslog(LOG_INFO, "Config parse done");
	daemon(0, 0);
	pid = fork();

	if(pid != 0) { /* Parent */

	} else {/* Child */
		start_mail_relay(argv[1], strtol(argv[2], NULL, 10));
	}
	/* NOTREACHED */
	return 0;
}
