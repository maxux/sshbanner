#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <stdint.h>
#include "fwlban.h"
#include "modules.h"
#include "misc.h"

int fwlban_ban(remote_t *remote, module_t *module) {
	char buffer[256];
	ip_explode_t explode;
	module_rule_list_t *rules;
	
	syslog(LOG_INFO, "Remote %s: %d request on %d seconds. Banned.", ip_from_int(remote->ip, buffer), remote->nbrequest, (unsigned int) (remote->last - remote->first));
	printf("[!] Banner: %d request on %d seconds -> Banning remote !\n", remote->nbrequest, (unsigned int) (remote->last - remote->first));
	
	if(remote->banned) {
		fprintf(stderr, "[-] Banner: WTF, client is theorically already ban !\n");
		return 3;
	}
	
	remote->banned = 1;
	explode = ip_split_from_int(remote->ip);
	
	rules = module->ban_rules;
	while(rules) {
		sprintf(buffer, rules->rule, explode.c1, explode.c2, explode.c3, explode.c4);
		printf("[!] Banner: %s\n", buffer);
		
		execute(buffer, EXECUTE_NO_SILENT);
		
		rules = rules->next;
	}
	
	return 0;
}

void fwlban_unban(remote_t *remote, module_t *module) {
	char buffer[256];
	ip_explode_t explode;
	module_rule_list_t *rules;
	
	/* Client banned */
	if(remote->banned) {
		explode = ip_split_from_int(remote->ip);
		
		printf("[+] Banner: unban <%u-%u-%u-%u>\n", explode.c1, explode.c2, explode.c3, explode.c4);
		
		/* Removing from iptables */
		rules = module->unban_rules;
		while(rules) {
			sprintf(buffer, rules->rule, explode.c1, explode.c2, explode.c3, explode.c4);
			printf("[!] Banner: %s\n", buffer);
			
			execute(buffer, EXECUTE_NO_SILENT);
			
			rules = rules->next;
		}
	}
	
	remote = remote->next;
}

void fwlban_unban_all(module_t *modules) {
	remote_t *remote;
	
	while(modules) {
		remote = modules->candidate;
		
		while(remote) {
			fwlban_unban(remote, modules);
			remote = remote->next;
		}
		
		modules = modules->next;
	}
}
