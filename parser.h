#ifndef __SSHBAN_PARSER_H
	#define __SSHBAN_PARSER_H
	
	#define DAEMON_MAXSIZE	32
	
	char * syslog_ng_remove_header(char *line);
	int word_length_wopid(char *str);
	int word_length(char *str);
	
	int log_parse(char *line, module_t *modules);
#endif
