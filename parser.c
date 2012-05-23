#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "fwlban.h"
#include "modules.h"
#include "parser.h"
#include "handle_ssh.h"
#include "handle_lighttpd.h"
#include "misc.h"

extern char verbose;

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

int log_parse(char *line, module_t *modules) {
	char *daemon, *log;
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
	timestamp = syslog_ng_timestamp(line);
	log = syslog_ng_remove_header(line);
	
	while(modules) {
		/* Checking daemon name */
		if(!strcmp(daemon, modules->name)) {
			/* Callback handler */
			modules->handle(log, timestamp, modules);
			free(daemon);
			
			return 0;
		}
		
		modules = modules->next;
	}
		
	free(daemon);
	return 1;
}
