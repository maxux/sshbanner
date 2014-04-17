#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include "fwlban.h"
#include "misc.h"

void diep(char *str) {
	perror(str);
	exit(EXIT_FAILURE);
}

int execute(char *cmd, int flag) {
	FILE *fp;
	char buffer[512], *truecmd;
	int line = 0;
	
	printf("[ ] Execute: %s\n", cmd);
	
	truecmd = (char*) malloc(sizeof(char) * strlen(cmd) + 6);
	strcpy(truecmd, cmd);
	strcat(truecmd, " 2>&1");
	
	fp = popen(truecmd, "r");
	if(!fp) {
		perror("fopen");
		return 1;
	}
	
	while(fgets(buffer, sizeof(buffer), fp)) {
		if(flag == EXECUTE_NO_SILENT)
			printf("[X] %s", buffer);
			
		line++;
	}
	
	/* Closing */
	fclose(fp);
	
	/* Cleaning */
	free(truecmd);
	
	/* Line should be == 0 if all worked */
	return line;
}

int signal_intercept(int signal, void (*function)(int)) {
	struct sigaction sig;
	int ret;
	
	/* Building empty signal set */
	sigemptyset(&sig.sa_mask);
	
	/* Building Signal */
	sig.sa_handler	 = function;
	
	/* Ignoring Zombies Process */
	sig.sa_flags	 = 0;
	
	/* Installing Signal */
	if((ret = sigaction(signal, &sig, NULL)) == -1)
		perror("sigaction");
	
	return ret;
}

uint32_t ip_from_string(char *line) {
	ip_explode_t ip;
	uint32_t value;
	
	if(!line)
		return 0;
	
	if(sscanf(line, "%u.%u.%u.%u", &ip.c1, &ip.c2, &ip.c3, &ip.c4) != 4) {
		printf("[-] sscanf failed\n");
		return 0;
	}
	
	// printf("[+] IP Parser: <%d-%d-%d-%d>\n", ip.c1, ip.c2, ip.c3, ip.c4);
	
	/* Building IP integer */
	value = ip.c4 + ip.c3 * 256 + ip.c2 * 256 * 256 + ip.c1 * 256 * 256 * 256;
	
	return value;
}

char *ip_from_int(uint32_t ip, char *buffer) {
	ip_explode_t explode;
	
	explode = ip_split_from_int(ip);	
	sprintf(buffer, "%u.%u.%u.%u", explode.c1, explode.c2, explode.c3, explode.c4);
	
	return buffer;
}

ip_explode_t ip_split_from_int(uint32_t ip) {
	ip_explode_t explode;
	
	explode.c4 = ip & 0xFF;
	explode.c3 = (ip >> 8) & 0xFF;
	explode.c2 = (ip >> 16) & 0xFF;
	explode.c1 = (ip >> 24) & 0xFF;
	
	return explode;
}

int month_from_name(char *name) {
	// Jan, Feb, Mar, Apr, May, Jun, Jul, Aug, Sep, Oct, Nov, Dec
	
	if(*name == 'S') return 9;	// Sep
	if(*name == 'O') return 10;	// Oct
	if(*name == 'N') return 11;	// Nov
	if(*name == 'D') return 12;	// Dec
	
	if(*name == 'J') {
		if(*(name + 1) == 'a') return 1;	// Jan
		if(*(name + 3) == 'n') return 6;	// Jun
		return 7;				// Jul
	}
	
	if(*name == 'M') {
		if(*(name + 2) == 'r') return 3;	// Mar
		return 5;				// May
	}
	
	if(*name == 'A') {
		if(*(name + 1) == 'p') return 4;	// Apr
		return 8;				// Aug
	}
	
	return 2;	// Feb
}

time_t syslog_ng_timestamp(char *timestamp) {
	time_t rawtime;
	struct tm * timeinfo;

	/* get current timeinfo and modify it to the user's choice */
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	
	// timeinfo->tm_year = 2012 - 1900;
	timeinfo->tm_mon  = month_from_name(timestamp) - 1;
	
	if(*(timestamp + 4) == ' ')
		timeinfo->tm_mday = atoi(timestamp + 5);	// Jan  1
	else
		timeinfo->tm_mday = atoi(timestamp + 4);	// Jan 10
	
	timeinfo->tm_hour = atoi(timestamp + 7);
	timeinfo->tm_min  = atoi(timestamp + 10);
	timeinfo->tm_sec  = atoi(timestamp + 13);

	return mktime(timeinfo);
}
