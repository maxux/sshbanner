#ifndef __FWLBAN_MODULES_H
	#define __FWLBAN_MODULES_H
	
	typedef struct module_rule_list_t {
		char *rule;
		struct module_rule_list_t *next;
		
	} module_rule_list_t;
	
	typedef struct module_t {
		/* daemon name */
		const char *name;
		
		/* function pointer to handling */
		int (*handle)(char *, time_t, struct module_t *);
		
		/* iptable chain name */
		char *chain;
		
		/* banning/unbanning rules list */
		struct module_rule_list_t *ban_rules;
		struct module_rule_list_t *unban_rules;
		
		/* short (small time/flood) values in hits/seconds */
		size_t short_maxreq_count;
		size_t short_maxreq_delay;
		
		/* long (bruteforce) values in hits/seconds */
		size_t long_maxreq_count;
		size_t long_maxreq_delay;
		
		/* list of candidate for ban */
		struct remote_t *candidate;
		
		/* next node */
		struct module_t *next;
		
	} module_t;
	
	typedef enum module_rule_type_t {
		BAN_RULE,
		UNBAN_RULE
		
	} module_rule_type_t;
	
	
	int module_init();
	int module_chain_init(module_t *modules);
	
	module_t * module_create(const char *name, int (*handle)(char *, time_t, struct module_t *));
	void module_rules_add(module_t *module, module_rule_type_t type, char *rule);
	size_t module_rules_count(module_rule_list_t *list);
	void module_set_limits(module_t *module, size_t short_count, size_t short_delay, size_t long_count, size_t long_delay);
	module_t * module_register(module_t *new);
	
	int module_check_remote(remote_t *remote, module_t *module);
	
	int modules_clean(module_t *modules);
#endif
