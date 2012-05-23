#ifndef __SSHBAN_H
	#define __SSHBAN_H
	
	typedef struct remote_t {
		uint32_t ip;
		
		time_t first;
		time_t last;
		
		size_t nbrequest;
		char banned;
		
		struct remote_t *next;
		
	} remote_t;
	
	typedef struct ip_explode_t {
		uint32_t c1;
		uint32_t c2;
		uint32_t c3;
		uint32_t c4;
		
	} ip_explode_t;
	
	typedef struct global_t {
		char hostname[64];
		short hostname_size;
		struct module_t *modules;
		
	} global_t;
	
	extern global_t global;
	
	#define OLD_AGE_TIMEOUT		60 * 5		/* 5 min */
#endif
