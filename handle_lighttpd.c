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

int lighttpd_handle(char *line, time_t timestamp, module_t *module) {
	(void) line;
	(void) timestamp;
	(void) module;
	return 0;
}

void __module_lighttpd_init() {
	module_t *module;
	
	module = module_create("lighttpd", lighttpd_handle);
	
	module_rules_add(module, BAN_RULE, "iptables -A INPUT -s __IP__ -j __CHAIN__");
	module_rules_add(module, BAN_RULE, "iptables -A FORWARD -s __IP__ -j __CHAIN__");
	
	module_rules_add(module, UNBAN_RULE, "iptables -D INPUT -s __IP__ -j __CHAIN__");
	module_rules_add(module, UNBAN_RULE, "iptables -D FORWARD -s __IP__ -j __CHAIN__");
	
	module_register(module);
}
