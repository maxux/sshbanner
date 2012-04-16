#ifndef __SSHBAN_MISC_H
	#define __SSHBAN_MISC_H

	void diep(char *str);
	int execute(char *cmd, int flag);
	
	int signal_intercept(int signal, void (*function)(int));
	
	uint32_t ip_from_string(char *line);
	char *ip_from_int(uint32_t ip, char *buffer);
	
	int month_from_name(char *name);
	time_t syslog_ng_timestamp(char *timestamp);
	
	#define EXECUTE_SILENT		1
	#define EXECUTE_NO_SILENT	2
#endif
