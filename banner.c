#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <syslog.h>

#include "parser.h"
#include "banner.h"
#include "misc.h"
#include "handle_ssh.h"

#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

#define LOG_BUFFER	1024

char verbose = 1;
system_t sys;

void sighandler(int sig) {
	switch(sig) {
		case SIGINT:
		case SIGTERM:
			printf("\n[+] Closing...\n");
			syslog(LOG_INFO, "Closing: flusing tables...");
			ssh_unban(sys.candidate);
			
			execute("iptables -F " SSHBAN_CHAIN, EXECUTE_NO_SILENT);
			execute("iptables -X " SSHBAN_CHAIN, EXECUTE_NO_SILENT);
		break;
	}
}

int main(int argc, char *argv[]) {
	int length, i = 0, rd, j;
	int fd, wd, log;
	char buffer[sizeof(struct inotify_event)];
	struct inotify_event *event;
	char logbuffer[LOG_BUFFER], *line;
	
	if(argc < 2) {
		fprintf(stderr, "Usage: %s log-filename\n", argv[0]);
		return 1;
	}
	
	/* Grabbing system informations */
	if(gethostname(sys.hostname, 64) != 0) {
		perror("[-] gethostname");
		return 1;
	}

	/* Initializing inotify */
	if((fd = inotify_init()) < 0) {
		perror("[-] inotify_init");
		return 1;
	}

	/* Monitoring log change */
	if((wd = inotify_add_watch(fd, argv[1], IN_MODIFY)) == -1) {
		perror("[-] inotify_add_watch");
		return 1;
	}
	
	/* Init syslog */
	openlog("sshbanner", LOG_PID | LOG_NOWAIT, LOG_DAEMON);
	syslog(LOG_INFO, "Initializing...");
	
	/* Opening log file */
	if((log = open(argv[1], O_RDONLY)) == -1) {
		perror("[-] open");
		return 1;
	}
	
	/* Signal Handling */
	signal_intercept(SIGINT, sighandler);
	signal_intercept(SIGTERM, sighandler);
	
	/* Init System */
	sys.candidate = NULL;
	
	execute("iptables -F " SSHBAN_CHAIN, EXECUTE_SILENT);
	execute("iptables -X " SSHBAN_CHAIN, EXECUTE_SILENT);
	
	if(execute("iptables -N " SSHBAN_CHAIN, EXECUTE_NO_SILENT))
		fprintf(stderr, "[-] Warning: ssh chain seems to failed\n");
	
	if(execute("iptables -A " SSHBAN_CHAIN " -j DROP", EXECUTE_NO_SILENT))
		fprintf(stderr, "[-] Warning: ssh banning rulz seems to failed\n");

	printf("[+] Banner: waiting message...\n");
	/* Waiting */
	while((length = read(fd, buffer, sizeof(struct inotify_event))) > 0) {
		for(i = 0; i < length; i += sizeof(struct inotify_event) + event->len) {
			event = (struct inotify_event *) &buffer[i];
			
			/* Going near of the end of file */
			if(lseek(log, -LOG_BUFFER, SEEK_END) == -1)
				if(lseek(log, 0, SEEK_SET) == -1)
					perror("[-] lseek");
			
			/* Reading to buffering */
			if((rd = read(log, logbuffer, LOG_BUFFER)) == -1) {
				perror("[-] read");
				break;
			}
			
			logbuffer[rd - 1] = '\0';
			
			/* Gabbing last line */
			line = logbuffer;
			
			for(j = rd - 2; j > 0; j--) {
				if(logbuffer[j] == '\n') {
					line = logbuffer + j + 1;
					break;
				}
			}
			
			log_parse(line);
		}
	}
	
	perror("[-] read");
	
	/* Cleaning */
	inotify_rm_watch(fd, wd);
	close(fd);
	close(log);
	
	closelog();

	return 0;
}
