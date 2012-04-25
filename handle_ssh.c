#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <ctype.h>
#include <syslog.h>
#include "banner.h"
#include "handle_ssh.h"
#include "candidate_stack.h"
#include "misc.h"

extern system_t sys;

char *ssh_rulz_append[] = {
	"iptables -A INPUT -s %u.%u.%u.%u -j " SSHBAN_CHAIN,
	"iptables -A FORWARD -s %u.%u.%u.%u -j " SSHBAN_CHAIN
};

char *ssh_rulz_delete[] = {
	"iptables -D INPUT -s %u.%u.%u.%u -j " SSHBAN_CHAIN,
	"iptables -D FORWARD -s %u.%u.%u.%u -j " SSHBAN_CHAIN
};

void ssh_unban(remote_t *remote) {
	unsigned int i;
	char buffer[256];
	ip_explode_t explode;
	
	/* Removing banned remote */
	while(remote) {
		/* Client banned */
		if(remote->banned) {
			explode.c4 = remote->ip & 0xFF;
			explode.c3 = (remote->ip >> 8) & 0xFF;
			explode.c2 = (remote->ip >> 16) & 0xFF;
			explode.c1 = (remote->ip >> 24) & 0xFF;
			
			printf("[+] Banner: unban <%u-%u-%u-%u>\n", explode.c1, explode.c2, explode.c3, explode.c4);
			
			/* Removing from iptables */
			for(i = 0; i < sizeof(ssh_rulz_delete) / sizeof(char*); i++) {
				sprintf(buffer, ssh_rulz_delete[i], explode.c1, explode.c2, explode.c3, explode.c4);
				execute(buffer, EXECUTE_NO_SILENT);
			}
		}
		
		remote = remote->next;
	}
}

int ssh_handle(char *line, time_t timestamp) {
	remote_t *temp;
	uint32_t ip = 0;
	ip_explode_t explode;
	char buffer[128];
	unsigned int i;
	int score = 1;
	
	if(!line) {
		printf("[-] SSH: Empty parsing line, skipping...\n");
		return 1;
	}
	
	printf("[+] SSH: <%s>\n", line);
	
	/* Checking some message format */
	if(!strncmp(line, "SSH: Server;Ltype: Version;Remote:", 34)) {
		ip = ip_from_string(line + 35);
		printf("[+] SSH: Pre-auth request (%u)\n", ip);
		
	} else
	
	if(!strncmp(line, "SSH: Server;Ltype: Kex", 22)) {
		ip = ip_from_string(line + 31);
		printf("[+] SSH: Pre-auth request (%u)\n", ip);
	} else
	
	if(!strncmp(line, "pam_unix(sshd:auth): authentication failure;", 44)) {
		ip = ip_from_string(strstr(line, "rhost=") + 6);
		printf("[+] SSH: Authentification failed (%u)\n", ip);
		
	} else
	
	if(!strncmp(line, "Invalid user", 12)) {
		ip = ip_from_string(strstr(line, "from") + 5);
		printf("[+] SSH: User request failed (%u)\n", ip);
		score = 2;
	}
	
	/* Checking match */
	if(!ip) {
		printf("[-] SSH: Message not parsed\n");
		return 1;
	}
	
	/* Updating Request List */
	temp = stack_search(ip);
	if(!temp) {
		printf("[ ] Stack: New Client\n");
		
		temp = (remote_t*) malloc(sizeof(remote_t));
		if(!temp)
			diep("malloc");
			
		temp->ip	= ip;
		temp->first	= timestamp;
		temp->last	= timestamp;
		temp->nbrequest	= 0;
		temp->banned	= 0;
		
		if(!stack_remote(temp)) {
			fprintf(stderr, "[-] cannot stack remote\n");
			return 2;
		}
		
	} else printf("[+] Client already known\n");
	
	/* Parsing Client */
	temp->nbrequest += score;
	temp->last = timestamp;
	
	/* Reset after long time */
	if(temp->first < (temp->last - OLD_AGE_TIMEOUT)) {
		printf("[+] Banner: Old Remote Client, resetting...\n");
		
		temp->first	= temp->last;
		temp->nbrequest	= 1;
		
		return 0;
	}
	
	if((temp->last < temp->first + LONG_MAX_REQUEST_DELAY && temp->nbrequest > LONG_MAX_REQUEST_COUNT) ||
	   (temp->last < temp->first + SHORT_MAX_REQUEST_DELAY && temp->nbrequest > SHORT_MAX_REQUEST_COUNT)) {
		   
		syslog(LOG_INFO, "Remote %s: %d request on %d seconds. Banned.", ip_from_int(ip, buffer), temp->nbrequest, (unsigned int) (temp->last - temp->first));
		printf("[!] Banner: %d request on %d seconds -> Banning remote !\n", temp->nbrequest, (unsigned int) (temp->last - temp->first));
		
		if(temp->banned) {
			printf("[-] Banner: WTF, client is theoretically already ban !\n");
			return 3;
		}
		
		temp->banned = 1;
		
		explode.c4 = ip & 0xFF;
		explode.c3 = (ip >> 8) & 0xFF;
		explode.c2 = (ip >> 16) & 0xFF;
		explode.c1 = (ip >> 24) & 0xFF;
		
		for(i = 0; i < sizeof(ssh_rulz_append) / sizeof(char*); i++) {
			sprintf(buffer, ssh_rulz_append[i], explode.c1, explode.c2, explode.c3, explode.c4);
			printf("[!] Banner: %s\n", buffer);
			
			execute(buffer, EXECUTE_NO_SILENT);
		}
	}
	
	stack_dump(sys.candidate);
	
	return 0;
}
