#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <stdint.h>
#include "fwlban.h"
#include "modules.h"
#include "misc.h"

/* User Defined Includes */
#include "handle_ssh.h"
#include "handle_lighttpd.h"

int module_init() {
	/* Init root node */
	global.modules = NULL;
	
	/* Modules/User initializations */
	__module_ssh_init();
	__module_lighttpd_init();
	
	return 0;
}

int module_chain_init(module_t *modules) {
	char cmdline[512];
	
	while(modules) {
		sprintf(cmdline, "iptables -F %s", modules->chain);
		execute(cmdline, EXECUTE_SILENT);
		
		sprintf(cmdline, "iptables -X %s", modules->chain);
		execute(cmdline, EXECUTE_SILENT);
		
		sprintf(cmdline, "iptables -N %s", modules->chain);
		if(execute(cmdline, EXECUTE_NO_SILENT))
			fprintf(stderr, "[-] Warning: ssh chain seems to failed\n");
		
		sprintf(cmdline, "iptables -A %s -j DROP", modules->chain);
		if(execute(cmdline, EXECUTE_NO_SILENT))
			fprintf(stderr, "[-] Warning: ssh banning rule seems to failed\n");
		
		modules = modules->next;
	}
	
	return 0;
}

module_t *module_create(const char *name, int (*handle)(char *, time_t, module_t *)) {
	module_t *module;
	
	module = (module_t*) malloc(sizeof(module_t));
	if(!module)
		diep("[-] malloc");
	
	
	module->chain = (char*) malloc(sizeof(char) * 64 + strlen(name));
	if(!module->chain)
		diep("malloc");
	
	sprintf(module->chain, "__fwlban_%s", name);
	
	module->name   = name;
	module->handle = handle;
	
	module->ban_rules   = NULL;
	module->unban_rules = NULL;
	
	module->short_maxreq_count = 0;
	module->short_maxreq_delay = 0;
	module->long_maxreq_count = 0;
	module->long_maxreq_delay = 0;
	
	module->candidate   = NULL;
	
	return module;
}

void module_set_limits(module_t *module, size_t short_count, size_t short_delay, size_t long_count, size_t long_delay) {
	module->short_maxreq_count = short_count;
	module->short_maxreq_delay = short_delay;
	
	module->long_maxreq_count = long_count;
	module->long_maxreq_delay = long_delay;
}

void module_rules_add(module_t *module, module_rule_type_t type, char *rule) {
	module_rule_list_t *item, **root;
	char temp[512];
	int n = 0;
	
	item = (module_rule_list_t*) malloc(sizeof(module_rule_list_t));
	if(!item)
		diep("[-] malloc");
		
	item->rule  = (char*) malloc(sizeof(char) * strlen(rule) + strlen(module->chain) + 1);
	*item->rule = '\0';
	
	while(sscanf(rule, "%s%n", temp, &n) == 1) {
		if(!strcmp(temp, "__CHAIN__"))
			strcat(item->rule, module->chain);
		
		else if(!strcmp(temp, "__IP__"))
			strcat(item->rule, "%u.%u.%u.%u");
			
		else strcat(item->rule, temp);
		
		strcat(item->rule, " ");
		rule += n;
	}
	
	// printf("[ ] Module: rule add: %s\n", item->rule);
	
	/* Creating global worker */
	switch(type) {
		case BAN_RULE:
			root = &(module->ban_rules);
		break;
		
		case UNBAN_RULE:
			root = &(module->unban_rules);
		break;
		
		default:
			fprintf(stderr, "[-] Invalid ban type\n");
			exit(EXIT_FAILURE);
		break;
	}
	
	/* Working */
	item->next = *root;
	*root = item;
}

size_t module_rules_count(module_rule_list_t *list) {
	size_t length = 0;
	
	while(list) {
		length++;
		list = list->next;
	}
	
	return length;
}

module_t *module_register(module_t *module) {
	size_t ban = 0, unban = 0;
	
	ban   = module_rules_count(module->ban_rules);
	unban = module_rules_count(module->unban_rules);
	
	if(!module->short_maxreq_count || !module->short_maxreq_delay)
		printf("[W] Module: warning: %s: short values not set\n", module->name);
	
	if(!module->long_maxreq_count || !module->long_maxreq_delay)
		printf("[W] Module: warning: %s: long values not set\n", module->name);
	
	printf("[+] Module: registered: %s, %zu ban rules, %zu unban rules\n", module->name, ban, unban);
	
	/* Appending module */
	module->next = global.modules;
	global.modules = module;
	
	return global.modules;
}

int module_check_remote(remote_t *remote, module_t *module) {
	uint32_t exception = ip_from_string("192.168.10.0");
	
	if((remote->ip & exception) == exception) {
		printf("[-] ip on exception list\n");
		return 0;
	}
	
	return (
		(
			(size_t) remote->last < (size_t) remote->first + module->long_maxreq_delay &&
			remote->nbrequest > module->long_maxreq_count
		) || (
			(size_t) remote->last < (size_t) remote->first + module->short_maxreq_delay &&
			remote->nbrequest > module->short_maxreq_count)
		);
}

int modules_clean(module_t *modules) {
	char buffer[512];
	
	// TODO: free all
	while(modules) {
		sprintf(buffer, "iptables -F %s", modules->chain);
		execute(buffer, EXECUTE_NO_SILENT);
		
		sprintf(buffer, "iptables -X %s", modules->chain);
		execute(buffer, EXECUTE_NO_SILENT);
		
		modules = modules->next;
	}
	
	return 0;
}
