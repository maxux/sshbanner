#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "banner.h"
#include "parser.h"
#include "handle_ssh.h"
#include "misc.h"

extern char verbose;
extern system_t sys;

int word_length(char *str) {
	int i = 0;
	
	while(*(str+i) && *(str+i) != ' ')
		i++;
	
	return i;
}

int word_length_wopid(char *str) {
	int i = 0;
	
	while(*(str+i) && *(str+i) != ' ' && *(str+i) != '[')
		i++;
	
	return i;
}

char * syslog_ng_remove_header(char *line) {
	/* Skipping date */
	line += 15;
	
	while(*line && *line != ':')
		line++;
	
	return (*line) ? line + 2 : NULL;
}

int log_parse(char *line) {
	char *daemon;
	char *log;
	short hostsize;
	short daemonsize, truedaemonsize;
	time_t timestamp;
	
	/* printf("Raw: <%s>\n", line); */
	
	/* Skipping timestamp */
	log      = line + 16;
	hostsize = word_length(log);
	
	/* Reading daemon name */
	truedaemonsize	= word_length(log + hostsize + 1);
	daemonsize	= word_length_wopid(log + hostsize + 1);
	
	daemon = (char*) malloc(sizeof(char) * daemonsize + 1);
	
	strncpy(daemon, log + hostsize + 1, daemonsize);
	daemon[daemonsize] = '\0';
	
	/* printf("Daemon: %s\n", daemon); */
	
	/* Check for sshd */
	if(strcmp(daemon, "sshd")) {
		free(daemon);
		return 1;
	}
	
	/* Formating date */
	timestamp = syslog_ng_timestamp(line);
	
	/* Parsing sshd line */
	/* printf("It's SSH ! -> %d\n", timestamp); */
	
	ssh_handle(syslog_ng_remove_header(line), timestamp);
	
	return 0;
}
