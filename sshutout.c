/***************************************************************************\
**                                                                         **
** Name:      sshutout.c                                                   **
** Languages: C                                                            **
** Author:    Bill DuPree                                                  **
** Company:   TechFinesse						   **
** Date:      December 16, 2007					   	   **
** (C) Copyright 2007 by Bill DuPree, All rights reserved.                 **
**                                                                         **
** Purpose: This program runs as a daemon that monitors log files to watch **
** for crack attempts and dictionary attacks on the Secure Shell daemon,   **
** i.e. sshd or sshd2. If it finds what it thinks is an attack, it         **
** creates a firewall rule to block that IP address from access to the     **
** server for a preset period of time. Once that time has elapsed, the     **
** firewall rule is removed.                                               **
**                                                                         **
**                                                                         **
** LICENSE:                                                                **
**                                                                         **
** This program is free software; you can redistribute it and/or modify    **
** it under the terms of the GNU General Public License as published by    **
** the Free Software Foundation; either version 2 of the License, or       **
** (at your option) any later version.                                     **
**                                                                         **
** This program is distributed in the hope that it will be useful,         **
** but WITHOUT ANY WARRANTY; without even the implied warranty of          **
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           **
** GNU General Public License for more details.                            **
**                                                                         **
** You should have received a copy of the GNU General Public License       **
** along with this program; if not, write to the Free Software             **
** Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301   **
** USA                                                                     **
**                                                                         **
** CONTACT:                                                                **
**                                                                         **
** Email: bdupree@techfinesse.com                                          **
** Post: Bill DuPree, 609 Wenonah Ave, Oak Park, IL 60304-1031 USA         **
**                                                                         **
*****************************************************************************
**                                                                         **
** CHANGE LOG:                                                             **
**                                                                         **
** Date        Revision  Initials   Description of Changes                 **
** ----------------------------------------------------------------------- **
** 2006-05-30     1.0.0    BD       Initial version                        **
** 2006-06-12     1.0.1    BD       Fix crash for "identification string   **
**                                  from UNKNOWN" messages                 **
** 2006-06-18     1.0.2    BD       Fix to get actual default route as     **
**                                  opposed to first gateway encountered   **
**                                  in routing table. (My thanks to        **
**                                  Hansjürg Wenger!) Added option to      **
**                                  disable/enable automatic whitelisting  **
**                                  of default gw and name servers.        **
** 2006-06-28     1.0.3    BD       Add option to recognize "Illegal user" **
**                                  attempts.                              **
** 2007-11-08     1.0.4    BD       Made -u option recognize "Invalid      **
**                                  user" as well.                         **
**                                  (Thanks to Peter McClure!)             **
** 2007-12-30     1.0.5    BD       Fixed -u option (paper bag on head)    **
**                                  (Thanks to Ralph Slooten!)             **
** 2009-12-05     1.0.6    BD       Added detection for "UNKNOWN USER",    **
**                                  larger config file line buffer, and    **
**                                  corrected open() calls.                **
**                                  (Thanks to Michael Shigorin &          **
**                                  A.Kitouwaykin at ALT Linux)            **
**                                                                         **
\***************************************************************************/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <netdb.h>
#include <net/route.h>

#define VERSION "1.0.6"

/* Command line options */
#define OPTIONS "?2Dd:ef:hi:l:Pp:s:t:uw:"
extern char *optarg;
extern int optind, opterr, optopt;

/* Tokens used in parsing configuration file */
#define PARM_PENALTY   1
#define PARM_THRESHOLD 2
#define PARM_POLL      3
#define PARM_SSHD_LOG  4
#define PARM_LOG_FILE  5
#define PARM_DAEMON    6
#define PARM_PID_FILE  7
#define PARM_WHITELIST 8
#define PARM_PORTSCAN  9
#define PARM_AUTO_WHITELIST 10
#define PARM_ILLEGAL_USER 11

/* Some limits on user configurable parms */
#define MIN_POLL 30
#define MAX_POLL 300
#define MIN_PENALTY 60
#define MAX_PENALTY 86400
#define MIN_THRESHOLD 3

/* Normal default values if nothing else is specified in config file or on command line */
#define POLLING_INTERVAL   60
#define PENALTY            300
#define THRESHOLD          4
#define SSHD_LOG_FILE	  "/var/log/messages"
#define SSHD2_LOG_FILE    "/var/log/secure"
#define SSHUTOUT_LOG      "/var/log/sshutout.log"
#define SSHD_DAEMON       "sshd"
#define SSHD2_DAEMON      "sshd2"
#define PID_FILE          "/var/run/sshutout.pid"
#define CONF_FILE	  "/etc/sshutout.conf"

#define INBUFSIZE  1024
#define CFGBUFSIZE 32768

/* Preconfigured defaults for operation if nothing else is specified */
static int  polling_interval = POLLING_INTERVAL;
static long delay_penalty = PENALTY;
static long threshold = THRESHOLD;

/* Specific files that we operate upon */
static char sshd_log_file[INBUFSIZE];
static char sshutout_log[INBUFSIZE];
static char pid_file[INBUFSIZE];
static char conf_file[INBUFSIZE];

/* Specific external programs that we execute */
#define IFCONFIG "ifconfig"
#define IPTABLES "iptables"
static char iptables[64];
static char ifconfig[64];

static char *cmdpaths[] = { "/usr/local/sbin/", "/usr/sbin/", "/sbin/", "/usr/local/bin/", "/usr/bin/", "/bin/", NULL }; 

#define _PATH_PROCNET_ROUTE	"/proc/net/route"

#define DAEMON_PARM_SIZE 32
static char sshdaemon[DAEMON_PARM_SIZE];
static pid_t mypid;

/********************************************************************/ 
/* Structure used to list IP addresses we exclude from prosecution, */
/* i.e. our default route, name servers, out own addresses,         */
/* loopback, etc.                                                   */
/********************************************************************/ 
typedef struct excl {
	struct excl *next;
        u_int32_t ipaddr, mask;
} excl_ip;

static excl_ip *excl_list, *whitelist;

/***************************************************************************************/
/* Structure used to tally offenders gleaned from examining the ssh daemon log entries */
/***************************************************************************************/
typedef struct iplog {
	struct iplog *next;
        u_int32_t ipaddr, count;
        time_t t;
} logitem;

static logitem *loglist[256];
static logitem *blocklist;

static char *myname;    /* Name that we were invoked under */

/* Yuck! Global flags! */
static int portscan = 0;
static int attached = 1;
static int logging = 0;
static int daemonize = 1;
static int openssh = 1;
static int auto_whitelist = 1;
static int illegal_user = 0;

static FILE *log;

/* Sign on and copyright notice */
static char *signon="ver. " VERSION " -- "
		    "(C)Copyright 2009 - Bill DuPree\n"
		    "All rights reserved.\n\n";


static void scan_log_file(const char *log_file, time_t t);
static void check_firewalled_list(int flush_blocks);

/**************************************************************************/
/* Convert an IPv4 address in host order to familiar dotted quad notation */
/**************************************************************************/
static char *dotted_quad(u_int32_t ipaddr, char *dq)
{
        sprintf(dq, "%d.%d.%d.%d", (ipaddr >> 24) & 0x0ff, (ipaddr >> 16) & 0x0ff, (ipaddr >> 8) & 0x0ff, ipaddr & 0x0ff);
	return dq;
}

/*************************************************************************/
/* Log messages to system log files, and console if not already detached */
/*************************************************************************/
static void Syslog(int lvl, char *fmt, ...)
{
	va_list arglist, alist;

        va_start(arglist, fmt);
        va_copy(alist, arglist);

	if (logging) vsyslog(lvl, fmt, arglist);
        if (attached) {
        	vfprintf(stderr, fmt, alist);
                fflush(stderr);
        }
        va_end(arglist);
        va_end(alist);
}


/***************************************************************/
/* Stevens' system() function provides proper signal handling. */
/***************************************************************/
int system(const char *cmdstring)
{
	pid_t pid;
        int status;
        struct sigaction ignore, saveintr, savequit;
        sigset_t chldmask, savemask;

        if (cmdstring == NULL)
        	return(1);		/* always a command processor with UNIX */

	ignore.sa_handler = SIG_IGN;    /* ignore SIGINT and SIGQUIT */
        sigemptyset(&ignore.sa_mask);
        ignore.sa_flags = 0;
        if (sigaction(SIGINT, &ignore, &saveintr) < 0)
        	return(-1);
        if (sigaction(SIGQUIT, &ignore, &savequit) < 0)
        	return(-1);

        sigemptyset(&chldmask);		/* now block SIGCHLD */
        sigaddset(&chldmask, SIGCHLD);
        if (sigprocmask(SIG_BLOCK, &chldmask, &savemask) < 0)
        	return(-1);

        if ((pid = fork()) < 0) {

        	status = -1;		/* probably out of processes */

        } else if (pid == 0) {		/* child */

        	/* restore previous signal actions and reset signal mask */
                sigaction(SIGINT, &saveintr, NULL);
                sigaction(SIGQUIT, &savequit, NULL);
                sigprocmask(SIG_SETMASK, &savemask, NULL);

                execl("/bin/sh", "sh", "-c", cmdstring, (char *) 0);
                _exit(127);	/* exec error */

        } else {			/* parent */

        	while (waitpid(pid, &status, 0) < 0) {
                	if (errno != EINTR) {
                        	status = -1;	/* error other than EINTR from waitpid() */
                                break;
                        }
                }
        }

	/* Restore previous signal actions and reset signal mask */
        if (sigaction(SIGINT, &saveintr, NULL) < 0)
        	return(-1);
        if (sigaction(SIGQUIT, &savequit, NULL) < 0)
        	return(-1);
	if (sigprocmask(SIG_SETMASK, &savemask, NULL) < 0)
        	return(-1);

        return(status);
}

/**********************************/
/* Convert a string to upper case */
/**********************************/
char *strupr(char *str)
{
	char *p;

	if (str == NULL) return str;

	for (p = str; *p; p++)
        	*p = toupper(*p);
        return str;
}

/******************************************************/
/* Function to trim trailing whitespace from a string */
/******************************************************/
char *rtrim(char *str)
{
	unsigned int len;
	char *p = str;

	if (!str) return str;

	len = strlen(p);
	for (p += len - 1; len--; p--) {
		if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
			*p = '\0';
		else
			break;
	}
	return str;	
}

/******************************************************/
/* Function to trim leading whitespace from a string  */
/******************************************************/
char *ltrim(char *str)
{
	char *p;

	if (!str) return str;

	for (p = str; *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'; p++);
        if (p != str)
		memmove(str, p, strlen(p)+1);
	return str;
}

/***********************************************************/
/* Macro trims leading and trailing whitespace from string */
/***********************************************************/
#define TRIM(str) rtrim(ltrim((str)))

/******************************************************/
/* Convert hexadecimal string to binary unsigned long */
/******************************************************/
static unsigned long hextol(const char *s)
{
	int c;
	u_int32_t rc = 0;

        for (; *s && isxdigit((c = toupper(*s))); s++) {
        	rc <<= 4;
        	if (c >= '0' && c <= '9')
                	c -= '0';
                else
                	c = c - 'A' + 10;
                rc += c;
        }
        return rc;
}

/**************************************************************************/
/* Attempt to resolve a host name to an IPv4 address. Returns two things: */
/* An unsigned long with a host order IPv4 address (zero if failure) and  */
/* the character pointer that has been advanced past the character string */
/* supplying the host name.                                               */
/**************************************************************************/
static u_int32_t try_name_res(char **ip)
{
	struct hostent *h;
	char host_name[256];
        char *p;
        int i;
	u_int32_t ipaddr = 0;

        p = *ip;

        /* Parse the host name */ 
        for (i = 0; i < 254; i++) {
        	if (p[i] && (isalnum(p[i]) || p[i] == '-' || p[i] == '.'))
                	host_name[i] = p[i];
                else {
                	host_name[i] = 0;
                        break;
                }
        }

        /* Host name cannot begin with dash or dot */
        if (host_name[0] == 0 || host_name[0] == '-' || host_name[0] == '.') return 0;

        /* Resolve host name */
        h = gethostbyname(host_name);
        if ((h_errno == 0 || h_errno == 1) && h->h_addrtype == AF_INET && h->h_length == 4) {
                memcpy(&ipaddr, h->h_addr_list[0], sizeof(ipaddr));
                ipaddr = ntohl(ipaddr);
	        *ip = p + i;
        }
        return ipaddr;
}

/*************************************************************************/
/* Convert familar dotted quad IPv4 address to ulong using host ordering */
/* Returns 0 if there is a formatting or range  error.                   */
/*************************************************************************/
static u_int32_t cvt_ipv4(char **ip)
{
        long octet[4];
	char *p, *s, **t = ip;

        s = *ip;
        if (!strncmp(s, "UNKNOWN", 7)) return 0;
        if (!strncmp(s, "::ffff:", 7)) *ip = (s += 7);          /* Handle IPv4 mapped IPv6 notation */
        if (!isdigit(*s) || !(p = strchr(s, '.'))) return try_name_res(t);
        p += 1;
        if ((octet[0] = atol(s)) < 0 || (octet[0] > 255)) return try_name_res(t);
        s = *ip = p;
        if (!(p = strchr(s, '.'))) return try_name_res(t);
        p += 1;
        if ((octet[1] = atol(s)) < 0 || (octet[1] > 255)) return try_name_res(t);
        s = *ip = p;
        if (!(p = strchr(s, '.'))) return try_name_res(t);
        p += 1;
        if (!isdigit(*p)) return try_name_res(t);
        if ((octet[2] = atol(s)) < 0 || (octet[2] > 255)) return try_name_res(t);
        *ip = p;
        if ((octet[3] = atol(p)) < 0 || (octet[3] > 255)) return try_name_res(t);
        while (isdigit(*p)) p++;
        *ip = p;
        return (octet[0] << 24) + (octet[1] << 16) + (octet[2] << 8) + octet[3];
}

/*****************************************************************/
/*             K L U D G E  A L E R T ! ! !                      */
/* Function returns the IP address for the current default route */
/* Warning: I'm sure this is very specific to Linux 2.4 and 2.6  */
/*****************************************************************/
static u_int32_t dflt_route()
{
        FILE *h;
        char *p, *iface, *dst, *gateway, *flags, buf[INBUFSIZE];
        u_int32_t rt = 0;

	if ((h = fopen(_PATH_PROCNET_ROUTE, "r"))) {

        	fgets(buf, INBUFSIZE, h);	/* Skip column header record */

        	while (fgets(buf, INBUFSIZE, h)) {

                	strupr(TRIM(buf));

                        p = iface = buf;
                        while (isalnum(*p)) p++;
                        if (!*p) continue;
                        *p++ = 0;
                        while (isspace(*p)) p++;
                        if (!*p) continue;

                        dst = p;
                        while (isalnum(*p)) p++;
                        if (!*p) continue;
                        *p++ = 0;
                        while (isspace(*p)) p++;
                        if (!*p) continue;
                        if (strncmp(dst, "00000000", 8)) continue;

                        gateway = p;
                        while (isalnum(*p)) p++;
                        if (!*p) continue;
                        *p++ = 0;
                        while (isspace(*p)) p++;
                        if (!*p) continue;

                        flags = p;
                        while (isalnum(*p)) p++;
                        if (!*p) continue;
                        *p++ = 0;

                        if ((hextol(flags) & (RTF_UP | RTF_GATEWAY)) == (RTF_UP | RTF_GATEWAY)) {
                        	rt = ntohl(hextol(gateway));
                                break;
                        }

                }
        	fclose(h);
        }
        return rt;
}

/**************************************************************************************/
/* This function tests if the given IP address is in the lists of excluded addresses. */
/* It returns 1 of the address is in the list, 0 otherwise.                           */
/**************************************************************************************/
static int in_exclusion_list(u_int32_t ipaddr)
{
	excl_ip *list;

        /******************************************************************/
        /* We search two lists. One is given by the current system config */
        /* in excl_list. The other, whitelist, is user definable via the  */
        /* configuration file.                                            */
        /******************************************************************/
        for (list = excl_list; list; list = list->next) {
        	if (list->ipaddr == ipaddr || (list->mask &&
                    (ipaddr == (list->ipaddr & list->mask) ||     	/* network and bcast are bogus and excluded */
                    ipaddr == (list->ipaddr | ~list->mask)))) return 1;

        }
        for (list = whitelist; list; list = list->next) {
        	if (list->ipaddr == ipaddr) return 1;
        }

	if (ipaddr == 0 || ipaddr == 0xffffffff || (ipaddr & 0xff000000) == 0x7f000000) return 1;

	return 0;
}

/***************************************************************/
/* Add the given IP address to the head of the exclusion list. */
/***************************************************************/
static void add_exclusion(u_int32_t ipaddr, u_int32_t mask)
{
	excl_ip *item;

        if (in_exclusion_list(ipaddr)) return;

        if (!(item = malloc(sizeof(excl_ip)))) {
        	Syslog(LOG_ERR, "Out of memory\n");
                return;
        }

        item->next = excl_list;
        item->ipaddr = ipaddr;
        item->mask = mask;
        excl_list = item;

        /* Syslog(LOG_DEBUG, "Adding exclusion ip: %ld.%ld.%ld.%ld\n",
                  (ipaddr >> 24) & 0x0ff, (ipaddr >>16) & 0x0ff, (ipaddr >> 8) & 0x0ff, ipaddr & 0x0ff); */
}

/***********************************************************************/
/* Examine the system configuration to get a list of IPv4 addresses to */
/* exclude from any firewalling actions, e.g. the default route, the   */
/* configured interfaces, and the name servers.                        */
/***********************************************************************/
static void create_exclusion_list(int create)
{
	FILE *p;
        char *ip, *s, buf[INBUFSIZE];
	char cmd[256];
        u_int32_t ipaddr, mask;
        excl_ip *list, *next;
        int n;

        snprintf(cmd, 256, "%s\n", ifconfig);

        /********************************/
        /* Clear out old exclusion list */
        /********************************/

        list = excl_list;
        excl_list = NULL;

        while (list) {
        	next = list->next;
                free(list);
                list = next;
        }

        if (!create) return;

        /*******************************/
        /* Create a new exclusion list */
        /*******************************/

	/* Execute ifconfig to get IPv4 addresses for all local interfaces */
        if (!(p = popen(cmd, "r"))) {
        	Syslog(LOG_ERR, "Pipe creation failure for command: %s\n", cmd);
        }
        else {
		while (fgets(buf, INBUFSIZE, p)) {
        		TRIM(buf);
	                if (!strncmp(buf, "inet ", 5)) {
        	        	ip = buf+5;
                                while (*ip && !isdigit(*ip)) ip++;
				if ((s = strchr(ip, ' ')) || (s = strchr(ip, '\t'))) {
                        		if ((s = strstr(s, "Mask:"))) {
                                        	s += 5;
                                        	mask = cvt_ipv4(&s);
                                        }
                                        else
                                        	mask = 0;
                                	if ((ipaddr = cvt_ipv4(&ip))) {
                                		add_exclusion(ipaddr, mask);
	                                }
        	                }
                	}
	        }

        	pclose(p);
        }

	/* Add IP address for default route */
        if ((ipaddr = dflt_route())) {
        	add_exclusion(ipaddr, 0);
        }

        /* Add IP addresses for name servers */
        if (!(p = fopen("/etc/resolv.conf", "r"))) {
        	Syslog(LOG_ERR, "Cannot open file: /etc/resolv.conf\n");
        }
        else {

        	n = 0;

		while (fgets(buf, INBUFSIZE, p)) {

        		TRIM(buf);

	                if (!memcmp(buf, "nameserver", 10)) {

        	        	ip = buf+10;

		                while (isspace(*ip)) ip++;

                                if ((ipaddr = cvt_ipv4(&ip)) && n < 3) {
                                	add_exclusion(ipaddr, 0);
                                        n += 1;
	                        }
                	}
	        }

        	pclose(p);
        }
}

/**************************************************************/
/* Quick Hack:                                                */
/* Convert three letter month abbreviation to a numeric value */
/* where 'Jan' == 0, 'Feb' == 1, etc. Return -1 if invalid.   */
/**************************************************************/
static int month_no(char *mo)
{
	int rc = 0;

        if (!strcmp(mo, "Jan")) return rc;
        rc += 1;
        if (!strcmp(mo, "Feb")) return rc;
        rc += 1;
        if (!strcmp(mo, "Mar")) return rc;
        rc += 1;
        if (!strcmp(mo, "Apr")) return rc;
        rc += 1;
        if (!strcmp(mo, "May")) return rc;
        rc += 1;
        if (!strcmp(mo, "Jun")) return rc;
        rc += 1;
        if (!strcmp(mo, "Jul")) return rc;
        rc += 1;
        if (!strcmp(mo, "Aug")) return rc;
        rc += 1;
        if (!strcmp(mo, "Sep")) return rc;
        rc += 1;
        if (!strcmp(mo, "Oct")) return rc;
        rc += 1;
        if (!strcmp(mo, "Nov")) return rc;
        rc += 1;
        if (!strcmp(mo, "Dec")) return rc;
        return -1;
}

/*********************************************************/
/* Execute iptables to block an offender at our firewall */
/*********************************************************/
static void blockip(logitem *item, time_t t)
{
	char cmd[256], ip[24];
        u_int32_t ipaddr = item->ipaddr;

	dotted_quad(ipaddr, ip);

	if (item->count) {
		Syslog(LOG_NOTICE, "Squelching attack from %s (%ld ssh login attempts) for %ld seconds.\n", ip, item->count, delay_penalty);
        }
        else {
		Syslog(LOG_NOTICE, "Squelching ssh port scan from %s for %ld seconds.\n", ip, delay_penalty);
        }

        item->count = 0;

        sprintf(cmd, "%s -I INPUT -s %s -j DROP\n", iptables, ip);
        system(cmd);

	fprintf(log, "%s blocked on %s", ip, ctime(&t));
}

/***************************************************************************/
/* Execute iptables to remove the offender's IPv4 adress from our firewall */
/***************************************************************************/
static void unblockip(char *ip)
{
	char cmd[256];

        sprintf(cmd, "%s -D INPUT -s %s -j DROP\n", iptables, ip);
        system(cmd);
}

/*************************************************************************/
/* Examine the list of currently firewalled IPv4 addresses to determine  */
/* which of the items is eligible to be removed due to the expiration of */
/* their penalty timeout. If the expiration interval has elapsed, remove */
/* the item from the list and unblock its IPv4 address at the firewall.  */
/* If it is not expiring, bump its expiry counter by one.                */
/*************************************************************************/
static void check_firewalled_list(int flush)
{
	logitem *prev, *current;
        char ip[24];

	prev = (logitem *)&blocklist;
	current = blocklist;

	while (current) {

		current->count += 1;

        	if (current->count >= delay_penalty || flush) {
                	prev->next = current->next;

			dotted_quad(current->ipaddr, ip);

                        if (flush)
				Syslog(LOG_NOTICE, "Unblocking %s prior to daemon termination.\n", ip);
                        else
				Syslog(LOG_NOTICE, "Unblocking %s after expiry of %ld seconds.\n", ip, delay_penalty);

                        unblockip(ip);
                        free(current);
                        current = prev->next;
                }
                else {
                	prev = current;
                	current = current->next;
                }
        }
}

/*****************************************************************************/
/* Scan the tally of items from our last pass of the log file, and for those */
/* items that have exceeded the allowable threshold of login attempts, block */
/* their IPv4 address at the firewall (using iptables) and transfer them to  */
/* blocked list. The remainder are discarded. A count of the number of items */
/* added to the firewall list is returned.                                   */
/*****************************************************************************/
static int check_thresholds(time_t t)
{
        int i, rc;
        logitem *prev, *list, *blocked;
	char ip[24];

	for (rc = i = 0; i < 256; i++) {

		list = loglist[i];
                loglist[i] = NULL;

                while (list) {

	        	prev = list;
        	        list = list->next;

                        if (prev->count >= threshold || prev->count == 0) {	/* count == 0 indicates a portscan to block */

				/* See if this one is already (supposedly) blocked */
                        	for (blocked = blocklist; blocked && blocked->ipaddr != prev->ipaddr; blocked = blocked->next);

                                if (!blocked) {
			                if (in_exclusion_list(prev->ipaddr)) {

                                        	/* Warn of possible probing from whitelisted source */
                                                dotted_quad(prev->ipaddr, ip);

                                        	Syslog(LOG_WARNING, "Warning: Possible attack from whitelisted IP address, %s\n", ip);
                                        	free(prev);
                                        }
                                        else {
                                        	/* Block the offender at the firewall */
                                		blockip(prev, t);
	                                        prev->next = blocklist;
        	                                blocklist = prev;
                	                        rc += 1;
                                        }
                                }
                                else {

                                        /***************************************************************************/
					/* Hmmmn... We still see attempts from an address we supposedly blocked... */
                                        /* Maybe iptables wasn't installed or built into the kernel?               */
                                        /***************************************************************************/
					dotted_quad(prev->ipaddr, ip);

                                       	Syslog(LOG_WARNING, "Warning: Possible failure to block IP address, %s\n", ip);

                                	blocked->t = prev->t;
                                        free(prev);
                                }
                        }
                        else {
                        	free(prev);
                        }
                }
        }
        return rc;
}

/***************************************************************************************************/
/* Check to see if the given IP address is in our list created for this pass through the log file. */
/* If it isn't present, add it to the list and set its login attempt count to 1. If its already    */
/* present, the bump its login attempt count by 1. Return a pointer to the list item.              */
/***************************************************************************************************/
static logitem *tally(u_int32_t ipaddr, time_t t)
{
	logitem *prev, *list;

	list = loglist[ipaddr & 0x0ff];
	prev = (logitem *)(loglist + (ipaddr & 0x0ff));

        while (list && list->ipaddr != ipaddr) {
        	prev = list;
                list = list->next;
        }

        if (list) {
        	list->count += 1;
                list->t = t;
                return list;
        }
        else {

        	if (!(prev->next = malloc(sizeof(logitem)))) {
                	Syslog(LOG_ERR, "Out of memory.\n");
			return NULL;
                }

                prev->next->ipaddr = ipaddr;
                prev->next->count = 1;
                prev->next->t = t;
                prev->next->next = NULL;
                return prev->next;
        }

        return NULL;
}

#define LOG_OPEN_ATTEMPTS 100

/*******************************************************************/
/* Scan the log file looking for repeated failed attempts to login */
/* through ssh.                                                    */
/*******************************************************************/
static void scan_log_file(const char *log_file, time_t t)
{
	FILE *h;
        static int errcount = 0;
        static long fpos = 0;
        struct tm start_tm;
        char inbuf[INBUFSIZE], dstr[DAEMON_PARM_SIZE+1];
        char *mo, *day, *timestr, *hostnm, *daemon, *msg, *pid, *p, *s;
        int x, start_timestamp, log_timestamp, attempt;
        u_int32_t ipaddr = 0;
        time_t t0;

        attempt = 0;
        strcpy(dstr, sshdaemon);
        strcat(dstr, "[");

        /* Open the log file */
        if (!(h = fopen(log_file, "r"))) {

		/* Alert user to likely misconfiguration */
                Syslog(LOG_ERR, "Failed to open input file: %s\n", log_file);

		/* If our repeated warning are ignored, we might as well not continue to clutter the logs */
                if (++errcount >= LOG_OPEN_ATTEMPTS) {

                	/* I don't need to stick around for this kind of abuse... */
                	Syslog(LOG_NOTICE, "Daemon has no usable input log file after %d attempts. Terminating.\n", errcount);
			for (;;) { raise(SIGTERM); sleep(10); }
                }
                return;
        }
        errcount = 0;

        /* Skip over stuff we've already scanned */
        fseek(h, 0, SEEK_END);
        if (fpos > ftell(h)) {
		rewind(h);
                fpos = 0;
        }
        else {
	        fseek(h, fpos, SEEK_SET);
	}

	/* Figure out where, chronologically speaking, we want to start examining log entries */ 
        t0 = t - polling_interval;
        localtime_r(&t0, &start_tm);
        start_timestamp = start_tm.tm_sec +
                          start_tm.tm_min * 60 +
                          start_tm.tm_hour * 3600 +
                          (start_tm.tm_mday << 17) +
                          (start_tm.tm_mon << 23);

        /********************************************************************************************/
	/* Tally the list of offending IP addresses attempting to repeatedly connect to ssh daemon. */
        /********************************************************************************************/

        while (fgets(inbuf, INBUFSIZE, h)) {

        	/* Parse out various components of the line from the log file */
                mo = inbuf;
                if (!(p = strchr(mo, ' '))) { attempt = 0; continue; }
                *p++ = 0;
                if ((x = month_no(mo)) < 0) { attempt = 0; continue; }
                if (start_tm.tm_mon == 11 && x == 0) x = 12; /* Handle wrapping at end of yr */

                day = p;
                while (*day && !isdigit(*day)) day++;
                if (!(p = strchr(day, ' '))) { attempt = 0; continue; }
                *p++ = 0;

                timestr = p;
                if (!(p = strchr(timestr, ' '))) { attempt = 0; continue; }
                *p++ = 0;

                hostnm = p;
                if (!(p = strchr(hostnm, ' '))) { attempt = 0; continue; }
                *p++ = 0;

                daemon = p;
                if (!strncmp(daemon, "last", 4)) {
                	msg = p;
                }
                else {

	                if (!(p = strchr(daemon, ' '))) { attempt = 0; continue; }
        	        *p++ = 0;

                	if (strncmp(daemon, dstr, strlen(dstr))) { attempt = 0; continue; }
			msg = p;
        	        p = strchr(daemon, '[');
                	*p++ = 0;

	                pid = p;
        	        if (!(p = strchr(pid, ']'))) { attempt = 0; continue; }
                	*p = 0;
                }

                /* Examine the timestamp on this line. It must be greater chronologically than the start timestamp */
                if (!(p = strchr(timestr, ':'))) { attempt = 0; continue; }
                *p++ = 0;

                log_timestamp = atoi(timestr) * 3600;
                timestr = p;
                if (!(p = strchr(timestr, ':'))) { attempt = 0; continue; }
                *p++ = 0;

                log_timestamp += atoi(timestr) * 60 + atoi(p) + (atoi(day) << 17) + (x << 23);

                if (log_timestamp < start_timestamp) { attempt = 0; continue; }

                /* If we have a login attempt followed by "last message repeated..." then count the repeats */
                if (attempt && !(strncmp(msg, "last message repeated", 21))) {
                	p = msg + 21;
                        while (*p && !isdigit(*p)) p++;
                        for (attempt = atoi(p); attempt && tally(ipaddr, t); attempt--);
                	continue;
		}

                /* openssh logging differs from sshd2 (which is free for nonprofit use from ssh.com) */
                if (openssh) {

			/* Check if we're blocking port scans. If so, check for a port scan */
                	if (portscan && !(strncmp(msg, "Did not receive identification string from", 42))) {
                        	logitem *item;

	                        if (!(p = strstr(msg, "from "))) { attempt = 0; continue; }
        	                p += 5;
		                if ((ipaddr = cvt_ipv4(&p)) == 0) { attempt = 0; continue; }
		                if (!(item = tally(ipaddr, t))) break;

				/* Special flag to indicate port was scanned */
                                item->count = 0;	/* No actual login attempt, but port was scanned. Trip the block. */
                                attempt = 0;
                        	continue;
			}

                        /* Check for login failure or illegal/invalid user */
                        if (strncmp(msg, "Failed", 6) &&
                            !strstr(msg, "error: PAM:") &&
			    (!illegal_user || (strncmp(msg, "Illegal user", 12) && strncmp(msg, "Invalid user", 12) 
                                              && strncmp(msg, "UNKNOWN USER", 12)))) { 
				attempt = 0;
				continue;
			}

                        /* Parse out address from login failure */
                        if (!(p = strstr(msg, "from "))) { attempt = 0; continue; }
                        p += 5;

                        if ((s = strstr(p, "from "))) p = s + 5;	/* Just in case invalid user name is 'from' */

	                if ((ipaddr = cvt_ipv4(&p)) == 0) { attempt = 0; continue; }
                }
                else {

                	if (strncmp(msg, "connection from \"", 17)) { attempt = 0; continue; }
	                s = msg + 17;

        	        if (!(p = strchr(s, '"'))) { attempt = 0; continue; }

                	*p = 0;

	                if ((ipaddr = cvt_ipv4(&s)) == 0) { attempt = 0; continue; }
                }

                /* Tally the failed attempt at login */
                if (!tally(ipaddr, t)) break;
                attempt = 1;
        }

        fpos = ftell(h);
        fclose(h);

        /* Block all IP addresses that exceed threshold for connection attempts */
        if (check_thresholds(t)) fflush(log);
}

#define IDCHARS "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"

/*****************************************************************/
/* Rudimentary token parser for analyzing our configuration file */
/*****************************************************************/
static char *get_token(char *p, char *token_buf)
{
	int token_len = 0;
	char *t = token_buf;

        *t = 0;
        while (isspace(*p)) p++;	/* flush leading whitespace */

        if (isalpha(*p)) {
		while (strchr(IDCHARS, *p) && token_len < CFGBUFSIZE) { token_len += 1; *t++ = *p++; }
                *t = 0;
        }
        else if (isdigit(*p)) {
		while ((isdigit(*p) || *p == '.') && token_len < CFGBUFSIZE) { token_len += 1; *t++ = *p++; }
                *t = 0;
        }
        else if (*p == '=' || *p == ',') {
        	*t++ = *p++;
                *t = 0;
        }
        else if (*p) {
        	return NULL;
        }

	return p;
}

/*************************************************************************************************************/
/* Create a singly linked list of IPv4 adresses from a CSV list of ASCII hostnames and dotted quad addresses */
/*************************************************************************************************************/
static int get_ip_list(char *p, excl_ip **wl)
{
	excl_ip *t, *list = NULL;
        u_int32_t ipaddr;

        *wl = NULL;

	while (isspace(*p)) p++;	/* flush whitespace */

        while (*p) {

		if (!(ipaddr = cvt_ipv4(&p))) {
                	for (t = list; t; ) { list = t->next; free(t); t = list; }
                        Syslog(LOG_ERR, "Malformed address in whitelist\n");
                        return 1;
                }

                for (t = list; t; t = t->next) {
                	if (t->ipaddr == ipaddr) break;
                }

                if (!t && !in_exclusion_list(ipaddr)) {

			if (!(t = malloc(sizeof(excl_ip)))) {
        	        	for (t = list; t; ) { list = t->next; free(t); t = list; }
                	        Syslog(LOG_ERR, "Out of memory in get_ip_list()\n");
                        	return 1;
	                }

        	        t->next = list;
                        t->ipaddr = ipaddr;
                        t->mask = 0;
                	list = t;
                }

	        while (isspace(*p)) p++;	/* flush whitespace */

                if (!*p) break;

                if (*p != ',') {
                	for (t = list; t; ) { list = t->next; free(t); t = list; }
                        Syslog(LOG_ERR, "Comma delimiter expected in whitelist\n");
                        return 1;
                }

                p += 1;

	        while (isspace(*p)) p++;	/* flush whitespace */

                if (!*p) {
                	for (t = list; t; ) { list = t->next; free(t); t = list; }
                        Syslog(LOG_ERR, "Expecting address in whitelist\n");
                        return 1;
                }

        }

        *wl = list;
        return 0;
}

/*****************************************/
/* Parse options from configuration file */
/*****************************************/
static void load_config(char *conf_file)
{
	FILE *conf, *tmpfile;
        struct stat statbuf;
        int linenum, parm, tmp, pf, newlist;
        long tmpl;
        excl_ip *t, *wl;
        char *p, token[CFGBUFSIZE], inbuf[CFGBUFSIZE];

        newlist = 1;
        wl = NULL;

        if (!(conf = fopen(conf_file, "r"))) {
        	Syslog(LOG_NOTICE, "Unable to open config file: \"%s\". Default values used.\n", conf_file);
                return;
        }

        linenum = 0;

        while (fgets(inbuf, CFGBUFSIZE, conf)) {

        	linenum += 1;

		if ((p = strchr(inbuf, '#'))) *p = 0;			/* trim trailing comments */

        	TRIM(inbuf);                                            /* trim leading and trailing whitespace */

                if (!inbuf[0]) continue;				/* skip blank lines */

                if (!(p = get_token(inbuf, token))) {
                	Syslog(LOG_WARNING, "Syntax error in config file: %s on line %d\n", conf_file, linenum);
                        continue;
                }

                /* Get parameter name */
                if (! strcmp(token, "polling_interval")) {
                	parm = PARM_POLL;
                } else if (! strcmp(token, "delay_penalty")) {
                	parm = PARM_PENALTY;
                } else if (! strcmp(token, "threshold")) {
                	parm = PARM_THRESHOLD;
                } else if (! strcmp(token, "sshd_log_file")) {
                	parm = PARM_SSHD_LOG;
                } else if (! strcmp(token, "sshutout_log_file")) {
                	parm = PARM_LOG_FILE;
                } else if (! strcmp(token, "ssh_daemon")) {
                	parm = PARM_DAEMON;
                } else if (! strcmp(token, "pid_file")) {
                	parm = PARM_PID_FILE;
                } else if (! strcmp(token, "whitelist")) {
                	parm = PARM_WHITELIST;
                } else if (! strcmp(token, "squelch_portscan")) {
                	parm = PARM_PORTSCAN;
                } else if (! strcmp(token, "illegal_user")) {
                	parm = PARM_ILLEGAL_USER;
                } else if (! strcmp(token, "auto_whitelist")) {
                	parm = PARM_AUTO_WHITELIST;
                } else {
                	Syslog(LOG_WARNING, "Unknown parameter name: %s in config file: %s on line %d\n", token, conf_file, linenum);
                        continue;
                }

                /* Next token must be operator '=' */

                if (!(p = get_token(p, token)) || strcmp(token, "=")) {
                	Syslog(LOG_WARNING, "Error: Expected '=' operator in config file: %s on line %d\n", conf_file, linenum);
                        continue;
                }

		switch (parm) {

		case PARM_PENALTY:

	                if (!(p = get_token(p, token)) || *p || !isdigit(token[0])) {
	                	Syslog(LOG_WARNING, "Error: Expected integer parameter in config file: %s on line %d\n", conf_file, linenum);
	                        continue;
	                }

                        tmpl = atol(token);
                        if (tmpl < MIN_PENALTY || tmpl > MAX_PENALTY)
	                	Syslog(LOG_WARNING, "Error: Specified penalty: %ld is out of range in config file: %s on line %d\n", tmpl, conf_file, linenum);
                        else
	                        delay_penalty = tmpl;
                        continue;

                	break;

		case PARM_THRESHOLD:

	                if (!(p = get_token(p, token)) || *p || !isdigit(token[0])) {
	                	Syslog(LOG_WARNING, "Error: Expected integer parameter in config file: %s on line %d\n", conf_file, linenum);
	                        continue;
	                }

                        tmpl = atol(token);
                        if (tmpl < MIN_THRESHOLD)
	                	Syslog(LOG_WARNING, "Error: Specified threshold: %ld is out of range in config file: %s on line %d\n", tmpl, conf_file, linenum);
                        else
	                        threshold = tmpl;
                        continue;

                	break;

		case PARM_POLL:

	                if (!(p = get_token(p, token)) || *p || !isdigit(token[0])) {
	                	Syslog(LOG_WARNING, "Error: Expected integer parameter in config file: %s on line %d\n", conf_file, linenum);
	                        continue;
	                }

                        tmp = atoi(token);
                        if (tmp < MIN_POLL || tmp > MAX_POLL)
	                	Syslog(LOG_WARNING, "Error: Specified polling interval: %d is out of range in config file: %s on line %d\n", tmp, conf_file, linenum);
                        else
				polling_interval = tmp;

                        continue;

                	break;

		case PARM_SSHD_LOG:

		        while (isspace(*p)) p++;	/* flush leading whitespace */
                        if (stat(p, &statbuf) < 0)
                        	Syslog(LOG_ERR, "Cannot stat input log file: %s\n", p);
                        else
	                        strncpy(sshd_log_file, p, INBUFSIZE);
                	break;

		case PARM_LOG_FILE:

		        while (isspace(*p)) p++;	/* flush leading whitespace */
                        if (!strcmp(sshutout_log, p)) continue;
                        if (log) {
                        	if ((tmpfile = fopen(p, "a"))) {
                                	fclose(log);
	                        	log = tmpfile;
                                }
                                else {
					Syslog(LOG_ERR, "Failed to open new log file: %s\n", p);
                                        break;
                                }
                        }
        	        strncpy(sshutout_log, p, INBUFSIZE);
                	break;

		case PARM_DAEMON:

		        while (isspace(*p)) p++;	/* flush leading whitespace */
                        if (strcmp(p, "sshd") && strcmp(p, "sshd2")) {
                        	Syslog(LOG_WARNING, "Error: Invalid daemon specification: %s in config file: %s on line %d\n", p, conf_file, linenum);
                                continue;
			}
                        strcpy(sshdaemon, p);
                        if (!strcmp(sshdaemon, "sshd2"))
				openssh = 0;
                        else
                        	openssh = 1;
                	break;

		case PARM_PID_FILE:

		        while (isspace(*p)) p++;	/* flush leading whitespace */
                        if (!strcmp(pid_file, p)) continue;
		        if ((pf = open(p, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP)) == -1) {
        			Syslog(LOG_ERR, "Either there is a stale PID file: %s,"
                                	"or another instance of the daemon is running.\n", p);
		        }
                        else {
                        	char buf[16];

				sprintf(buf, "%d\n", mypid);
				write(pf, buf, strlen(buf));
				close(pf);
                        	unlink(pid_file);
                        	strncpy(pid_file, p, INBUFSIZE);
                        }
                	break;

		case PARM_WHITELIST:

                	t = whitelist;
                        whitelist = NULL;
			if (get_ip_list(p, &wl)) newlist = 0;
                        whitelist = t;
                	break;

                case PARM_PORTSCAN:

		        while (isspace(*p)) p++;	/* flush leading whitespace */
                        if (!strcasecmp(p, "yes") || !strcasecmp(p, "y") || !strcasecmp(p, "t") || !strcasecmp(p, "true") || !strcmp(p, "1") || !strcasecmp(p, "on")) {
                        	portscan = 1;
                        } else if (!strcasecmp(p, "no") || !strcasecmp(p, "n") || !strcasecmp(p, "f") || !strcasecmp(p, "false") || !strcmp(p, "0") || !strcasecmp(p, "off")) {
                        	portscan = 0;
                        }
                        else
                        	Syslog(LOG_WARNING, "Invalid value: %s in config file: %s on line %d\n", p, conf_file, linenum);
  
                	break;

                case PARM_ILLEGAL_USER:

		        while (isspace(*p)) p++;	/* flush leading whitespace */
                        if (!strcasecmp(p, "yes") || !strcasecmp(p, "y") || !strcasecmp(p, "t") || !strcasecmp(p, "true") || !strcmp(p, "1") || !strcasecmp(p, "on")) {
                        	illegal_user = 1;
                        } else if (!strcasecmp(p, "no") || !strcasecmp(p, "n") || !strcasecmp(p, "f") || !strcasecmp(p, "false") || !strcmp(p, "0") || !strcasecmp(p, "off")) {
                        	illegal_user = 0;
                        }
                        else
                        	Syslog(LOG_WARNING, "Invalid value: %s in config file: %s on line %d\n", p, conf_file, linenum);
  
                	break;

                case PARM_AUTO_WHITELIST:

		        while (isspace(*p)) p++;	/* flush leading whitespace */
                        if (!strcasecmp(p, "yes") || !strcasecmp(p, "y") || !strcasecmp(p, "t") || !strcasecmp(p, "true") || !strcmp(p, "1") || !strcasecmp(p, "on")) {
                        	auto_whitelist = 1;
                        } else if (!strcasecmp(p, "no") || !strcasecmp(p, "n") || !strcasecmp(p, "f") || !strcasecmp(p, "false") || !strcmp(p, "0") || !strcasecmp(p, "off")) {
                        	auto_whitelist = 0;
                        }
                        else
                        	Syslog(LOG_WARNING, "Invalid value: %s in config file: %s on line %d\n", p, conf_file, linenum);
  
                	break;

                default:
                	Syslog(LOG_ERR, "Config file parsing bug in line %d of file: %s\n", linenum, conf_file);
                	break;
                }
        }

        fclose(conf);

        if (newlist) {
		for (t = whitelist; t; ) { whitelist = t->next; free(t); t = whitelist; }
		whitelist = wl;
        }
}

/*******************************************/
/* Output current configuration to the log */
/*******************************************/
static void log_config(int starting)
{
	excl_ip *t;
        char ip[24];

        if (starting) 
		Syslog(LOG_NOTICE, "*** The %s " VERSION " daemon has started ***\n", myname);
        else
        	Syslog(LOG_NOTICE, "*** %s " VERSION " is reloading configuration data ***\n", myname);

	Syslog(LOG_NOTICE, "%s configuration follows:\n", myname);
	Syslog(LOG_NOTICE, "Configuration file: %s\n", conf_file);
        Syslog(LOG_NOTICE, "SSH Daemon: %s\n", sshdaemon);
        Syslog(LOG_NOTICE, "Input log file: %s\n", sshd_log_file);
        Syslog(LOG_NOTICE, "Output log file: %s\n", sshutout_log);
        Syslog(LOG_NOTICE, "PID file: %s\n", pid_file);
        Syslog(LOG_NOTICE, "Polling interval: %d seconds\n", polling_interval);
        Syslog(LOG_NOTICE, "Threshold: %ld attempts\n", threshold);
        Syslog(LOG_NOTICE, "Delay penalty: %ld seconds\n", delay_penalty);
        Syslog(LOG_NOTICE, "Portscan squelching is %s\n", (portscan ? "enabled" : "disabled"));
	Syslog(LOG_NOTICE, "Illegal/Invalid user squelching is %s\n", (illegal_user ? "enabled" : "disabled"));
        Syslog(LOG_NOTICE, "Whitelist:\n");

        if (!excl_list && !whitelist) {
		Syslog(LOG_NOTICE, "  none\n");
        }
        else {

	        for (t = excl_list; t; t = t->next) {
        	        dotted_quad(t->ipaddr, ip);
                	Syslog(LOG_NOTICE, "  %s\n", ip);
	        }

        	for (t = whitelist; t; t = t->next) {
                	dotted_quad(t->ipaddr, ip);
	                Syslog(LOG_NOTICE, "  %s\n", ip);
        	}
        }
}

/*****************************************************/
/* Handle graceful termination on receipt of signal. */
/*****************************************************/
static void sig_handler(int sig)
{
	char *signames[_NSIG] = {"", "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP",
                                 "SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1",
			         "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT",
				 "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU",
                                 "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH",
                                 "SIGIO", "SIGPWR", "SIGSYS", "",
                                 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                                 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "" };

        /* If daemon gets a SIGHUP, then it refreshes its configuration from the config file */
	if (sig == SIGHUP) {
        	load_config(conf_file);
                create_exclusion_list(auto_whitelist);
                log_config(0);
        	return;
        }

	check_firewalled_list(1);		/* unblock all remaining blocked addresses upon exit */

	unlink(pid_file);

        Syslog(LOG_NOTICE, "*** The daemon has shut down with signal %d (%s) ***\n", sig, signames[sig]);

        closelog();
        exit(0);
}

/************************************/
/* Print hints as to command usage. */
/************************************/

static void usage()
{
        fprintf(stderr, "Usage:\n\t%s [-d delay] [-f config_file] [-i poll_interval]\n\t\t "
                        "[-l input_log_file] [-p pid_file] [-s output_log_file]\n\t\t "
                        "[-t threshold] [-w host_list] [-?] [-2] [-D] [-e] [-u]\n", myname);

        fprintf(stderr, "Where:\n"
                        "  -?  Gives this help message\n"
                        "  -2  Specifies that defaults for the sshd2 daemon are assumed\n"
                        "  -D  Means do not run as a daemon.\n"
                        "  -d  Takes a numeric value giving the number of seconds to firewall attackers\n"
                        "  -e  Turns off auto whitelisting of default route and name servers\n"
                        "  -f  Takes an alternate file name for the input configuration file\n"
                        "  -i  Takes a numeric value giving the polling interval in seconds\n"
                        "  -l  Takes an alternate file name for the input log file\n"
                        "  -P  Firewall IP addresses probing ssh port\n"
                        "  -p  Takes an alternate file name for the output PID file\n"
                        "  -s  Takes an alternate file name for the output log file\n"
                        "  -t  Takes a numeric threshold value for firewalling failed login attempts\n"
                        "  -u  Turn on sensitivity to \"Illegal/Invalid user\" attempts\n"
			"  -w  Takes a comma separated list of whitelisted host addresses\n");

        exit(0);
}

/***************/
/* Entry point */
/***************/
int main(int argc, char **argv)
{
	int i, opt, p, tmp, tpolling_interval, tportscan, tauto_whitelist, tillegal_user;
	sigset_t old_set, blocked_sigs;
	struct sigaction sa;
        time_t oldt, t;
	long tmpl, tdelay_penalty, tthreshold;
        char buf[16], *tsshutout_log, *tpid_file, *tsshdlogfile;
        excl_ip *wl, *w;
        struct stat statbuf;


        /* Setup initial sane default values */
	strcpy(sshd_log_file, SSHD_LOG_FILE);
        strcpy(sshutout_log, SSHUTOUT_LOG);
        strcpy(sshdaemon, SSHD_DAEMON);
        strcpy(pid_file, PID_FILE);
        strcpy(conf_file, CONF_FILE);

        wl = NULL;	/* Empty whitelist */

        time(&oldt);	/* get starting time */

	if ((myname = strrchr(argv[0], '/')) == NULL)
		myname = argv[0];
	else
		myname++;

	fprintf(stderr, "%s %s", myname, signon);

	/* Init override values */
        tauto_whitelist = tthreshold = tdelay_penalty = tpolling_interval = tportscan = tillegal_user = 0;
        tsshutout_log = tpid_file = tsshdlogfile = NULL;

        /* Parse command line options for overrides */
	while ((opt = getopt(argc, argv, OPTIONS)) != -1) {

        	switch (opt) {
                        case '2':
                        	openssh = 0;
                                break;

                	case 'D':
                        	daemonize = 0;
                                break;

                	case 'd':
                        	if ((tmpl = atol(optarg)) < MIN_PENALTY || tmpl > MAX_PENALTY) {
                                	fprintf(stderr, "Delay penalty must be in range 60-86400 seconds.\n");
                                        exit(1);
                                }
                                tdelay_penalty = tmpl;
                                break;

                        case 'e':
                        	tauto_whitelist = 1;
                                break;

                        case 'f':
				strncpy(conf_file, optarg, INBUFSIZE);     
                        	break;

                	case 'i':
                        	if ((tmp = atoi(optarg)) < MIN_POLL || tmp > MAX_POLL) {
                                	fprintf(stderr, "Polling interval must be in range 30-300 seconds.\n");
                                        exit(1);
                                }
                                tpolling_interval = tmp;
                                break;

                        case 'l':
                        	tsshdlogfile = optarg;
                                break;

                        case 'P':
                        	tportscan = 1;
                                break;

                        case 'p':
                                tpid_file = optarg;
                                break;

                        case 's':
                                tsshutout_log = NULL;
                                break;

                	case 't':
                        	if ((tmpl = atol(optarg)) < MIN_THRESHOLD) {
                                	fprintf(stderr, "Threshold must be greater than 2 connection attempts.\n");
                                        exit(1);
                                }
                                tthreshold = tmpl;
                                break;

                        case 'u':
				tillegal_user = 1;
                                break;

                        case 'w':
				get_ip_list(optarg, &wl);
                        	break;

                	default:
                        case 'h':
                	case '?':
                        	usage();
				exit(1);
                }
        }

        /* Anthing else on the command line is bogus */
        if (argc > optind) {

        	fprintf(stderr, "Extraneous args: ");

                for (i = optind; i < argc; i++) {
                	fprintf(stderr, "%s ", argv[i]);
                }

                fprintf(stderr, "\n\n");
                usage();
                exit(1);
        }

        /* Must be superuser to run the daemon */
	if (getuid() != 0) {
		fprintf(stderr, "Superuser authority is required.\n");
		exit(1);
	}

	/* Find the ifconfig and iptables commands. Different distros have different locations. */
        for (i = 0; cmdpaths[i]; i++) {
        	strcpy(ifconfig, cmdpaths[i]);
                strcat(ifconfig, IFCONFIG);
                if (stat(ifconfig, &statbuf) == 0) break;
                ifconfig[0] = 0;
        }

        if (!ifconfig[0]) {
        	fprintf(stderr, "Cannot find ifconfig command. Aborting.\n");
                exit(1);
        }

        for (i = 0; cmdpaths[i]; i++) {
        	strcpy(iptables, cmdpaths[i]);
                strcat(iptables, IPTABLES);
                if (stat(iptables, &statbuf) == 0) break;
                iptables[0] = 0;
        }

        if (!iptables[0]) {
        	fprintf(stderr, "Cannot find iptables command. Aborting.\n");
                exit(1);
        }

	/* Prevent more than one instance of the daemon from running. */
        if ((p = open(pid_file, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP)) == -1) {
        	fprintf(stderr, "Either there is a stale PID file: \"%s\",\n"
                                "or another instance of the daemon is running.\n", pid_file);
                exit(1);
        }

        fflush(stderr);

        /* set up syslog operation */
        openlog(myname, LOG_CONS | LOG_PID | LOG_ODELAY, LOG_DAEMON);
        logging = 1;

	/* Override default configuration with config file data */

        load_config(conf_file);

        /* Apply command line overrides last */
        if (!openssh) {
		strncpy(sshd_log_file, SSHD2_LOG_FILE, INBUFSIZE);
                strcpy(sshdaemon, SSHD2_DAEMON);
        }

        if (tsshdlogfile) strncpy(sshd_log_file, tsshdlogfile, INBUFSIZE);
        if (tdelay_penalty) delay_penalty = tdelay_penalty;
        if (tpolling_interval) polling_interval = tpolling_interval;
        if (tthreshold) threshold = tthreshold;
        if (tsshutout_log) strncpy(sshutout_log, tsshutout_log, INBUFSIZE);
        if (tpid_file) strncpy(pid_file, tpid_file, INBUFSIZE);
        if (tportscan) portscan = 1;
        if (tauto_whitelist) auto_whitelist = 0;
        if (tillegal_user) illegal_user = 1;

        if (wl) {

        	for (w = whitelist; w; ) {
                	whitelist = whitelist->next;
                        free(w);
                        w = whitelist;
                }

                whitelist = wl;
        }

        if (delay_penalty < polling_interval) {
        	Syslog(LOG_NOTICE, "Specified delay penalty: %ld < polling interval: %d. Value adjusted to equal polling interval.\n", delay_penalty, polling_interval);
                delay_penalty = polling_interval;
        }

        /* Open log file where we place the offender list */
        if (!(log = fopen(sshutout_log, "a"))) {
        	Syslog(LOG_CRIT, "Failed to open log file: %s\n", sshutout_log);
                exit(1);
        }

        /*****************************************************************/
        /* Whitelist our own IP addresses, nameservers and default route */
        /*****************************************************************/
	create_exclusion_list(auto_whitelist);

	log_config(1);		/* Dump current config to logs */

        /*************/
	/* Daemonize */
        /*************/
        if (daemonize) {
		if ((mypid = fork())) {

	            /* parent, or error */

	            if (mypid < 0)
        	    {
                	fprintf(stderr, "fork() failed\n");
	                close(p);
        	        unlink(pid_file);
                	exit(1);
	            }

	            /* Write child PID to PID file */
        	    sprintf(buf, "%d\n", mypid);
	            write(p, buf, strlen(buf));
        	    close(p);

	            /* parent exits */
        	    exit(0);
                }
        }
        else {
        	mypid = getpid();
		sprintf(buf, "%d\n", mypid);
		write(p, buf, strlen(buf));
        }

        /********************************************/
        /* Child.  Follow the daemon rules in       */
        /* W. Richard Stevens "Advanced Programming */
        /* in the UNIX Environment" (Addison-Wesley */
        /* Publishing Co., 1992). Page 417.).       */
        /********************************************/

        if (daemonize && setsid() < 0)
       	{
            Syslog(LOG_ERR, "Daemon not starting. setsid() failed: %m\n");
       	    unlink(pid_file);
            exit(1);
       	}

        chdir("/");
	if (daemonize) {
       		close(0);
        	close(1);
       		close(2);
                attached = 0;
        }
        close(p);
       	umask(0);

        /*************************************************************************/
	/* Handle signals.  SIGINT and SIGQUIT come from keyboard.  Ignore them. */
	/* We should never get them anyway (unless not running as a daemon.)     */
        /*************************************************************************/

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = 0;
	if (daemonize) {
		sa.sa_handler = SIG_IGN;
		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGQUIT, &sa, NULL);
        }

	/* What to do when somebody is telling us to shutdown. */
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGINT);
	sigaddset(&sa.sa_mask, SIGQUIT);
#ifndef _BSD
	sigaddset(&sa.sa_mask, SIGPWR);
#endif
	sigaddset(&sa.sa_mask, SIGTERM);
	sigaddset(&sa.sa_mask, SIGHUP);

	sigaction(SIGHUP, &sa, NULL); /* Re-read config, or lost connection to tty */
#ifndef _BSD
	sigaction(SIGPWR, &sa, NULL); /* Imminent power outage */
#endif
	/* Somebody wants to kill us! (No, I'm not paranoid! ;-) */
	sigaction(SIGTERM, &sa, NULL);
        if (!daemonize) {
		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGQUIT, &sa, NULL);
        }

	sigemptyset(&blocked_sigs);
	sigaddset(&blocked_sigs, SIGHUP);

	time(&t);

        /**************************************/
        /* Loop until we are signaled to stop */
        /**************************************/
        for (p = 0;; p++) {
        	struct timespec unslept;
                struct timeval now;
                u_int32_t frac;

                /*********************************************************/
                /* Assure timestamps only flow forward (no time travel!) */
                /* just in case superuser adjusts clock while daemon     */
                /* is running.                                           */
                /*********************************************************/
                if (t >= oldt) {
                	oldt = t;
                }
                else {
                	t = oldt;
                        if (p >= polling_interval)
				Syslog(LOG_WARNING, "Warning: Large time of day adjustments may impair daemon operation.\n");
                }

		check_firewalled_list(0);

		if (p >= polling_interval) {

			/* Make sure we can't HUP the daemon while accessing whitelists */
			sigprocmask(SIG_BLOCK, &blocked_sigs, &old_set);

	                create_exclusion_list(auto_whitelist);		/* Dynamically update exclusion list if config changes while running */
        	        scan_log_file(sshd_log_file, t);

                        /* Enable HUP signal again */
	                sigprocmask(SIG_SETMASK, &old_set, NULL);

                        p = 0;
                }

		/* Snooze until approximately the top of the next second */
                gettimeofday(&now, NULL);

                if ((frac = 1000000 - now.tv_usec) > 10000 && frac < 1000000) {
	                unslept.tv_sec = 0;
        	        unslept.tv_nsec = 1000 * frac;
                }
		else {
	                unslept.tv_sec = 1;
        	        unslept.tv_nsec = 0;
                }

                while (nanosleep(&unslept, &unslept) == EINTR);

                t = now.tv_sec + 1;
        }

        return 0;
}
