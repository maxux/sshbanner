#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <ctype.h>
#include <syslog.h>
#include "fwlban.h"
#include "modules.h"
#include "handle_ssh.h"
#include "banner.h"
#include "candidate_stack.h"
#include "misc.h"

int ssh_handle(char *line, time_t timestamp, module_t *module) {
	remote_t *temp;
	uint32_t ip = 0;
	char *test;	
	int score = 1;
	
	if(!line) {
		printf("[-] SSH: Empty parsing line, skipping...\n");
		return 1;
	}
	
	printf("[+] SSH: <%s>\n", line);
	
	/* Checking some message format */
	if(!strncmp(line, "SSH: Server;Ltype: Version;Remote:", 34)) {
		if(strlen(line) < 35) {
			fprintf(stderr, "Malformed line\n");
			return 1;
		}
		
		ip = ip_from_string(line + 35);
		printf("[+] SSH: Pre-auth request (%u)\n", ip);
		
	} else
	
	if(!strncmp(line, "SSH: Server;Ltype: Kex", 22)) {
		if(strlen(line) < 31) {
			fprintf(stderr, "Malformed line\n");
			return 1;
		}

		ip = ip_from_string(line + 31);		
		printf("[+] SSH: Pre-auth request (%u)\n", ip);
	} else
	
	if(!strncmp(line, "SSH: Server;Ltype: Authname", 27)) {
		if(strlen(line) < 36) {
			fprintf(stderr, "Malformed line\n");
			return 1;
		}

		ip = ip_from_string(line + 36);
		printf("[+] SSH: Pre-auth request (%u)\n", ip);
	} else
	
	if(!strncmp(line, "pam_unix(sshd:auth): authentication failure;", 44)) {
		if(!(test = strstr(line, "rhost="))) {
			fprintf(stderr, "Malformed line\n");
			return 1;
		}
		
		ip = ip_from_string(test + 6);
		printf("[+] SSH: Authentification failed (%u)\n", ip);
		
	} else
	
	if(!strncmp(line, "Invalid user", 12)) {
		if(!(test = strstr(line, "from"))) {
			fprintf(stderr, "Malformed line\n");
			return 1;
		}
		
		ip = ip_from_string(test + 5);
		printf("[+] SSH: User request failed (%u)\n", ip);
		score = 3;
	}
	
	/* Checking match */
	if(!ip) {
		printf("[-] SSH: Message not parsed\n");
		return 1;
	}
	
	/* Updating Request List */
	temp = stack_search(module->candidate, ip);
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
		
		if(!stack_remote(&module->candidate, temp)) {
			fprintf(stderr, "[-] Stack: Cannot stack remote\n");
			return 2;
		}
		
	} else printf("[+] Banner: Client already known: score: %zu, last: %zu\n", temp->nbrequest, temp->last);
	
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
	
	if(module_check_remote(temp, module)) {
		/* Apply ban */
		fwlban_ban(temp, module);
	}
	
	// stack_dump(module->candidate);
	
	return 0;
}

void __module_ssh_init() {
	module_t *module;
	
	module = module_create("sshd", ssh_handle);
	
	module_rules_add(module, BAN_RULE, "iptables -A INPUT -s __IP__ -j __CHAIN__");
	module_rules_add(module, BAN_RULE, "iptables -A FORWARD -s __IP__ -j __CHAIN__");
	
	module_rules_add(module, UNBAN_RULE, "iptables -D INPUT -s __IP__ -j __CHAIN__");
	module_rules_add(module, UNBAN_RULE, "iptables -D FORWARD -s __IP__ -j __CHAIN__");
	
	module_set_limits(module, 10, 15, 20, 60);
	
	module_register(module);
}
