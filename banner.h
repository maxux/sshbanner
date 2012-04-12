#ifndef __SSHBAN_H
	#define __SSHBAN_H
	
	typedef struct remote_t {
		uint32_t ip;
		
		time_t first;
		time_t last;
		
		int nbrequest;
		char banned;
		
		struct remote_t *next;
		
	} remote_t;
	
	typedef struct ip_explode_t {
		uint32_t c1;
		uint32_t c2;
		uint32_t c3;
		uint32_t c4;
		
	} ip_explode_t;
	
	typedef struct system_t {
		char hostname[64];
		short hostname_size;
		struct remote_t *candidate;
		
	} system_t;
	
	
	#define OLD_AGE_TIMEOUT		60 * 5		/* 5 min */
	
	/* This exemple: 30 requests failed on 50 seconds */
	#define SHORT_MAX_REQUEST_COUNT		15		/* 15 requests */
	#define SHORT_MAX_REQUEST_DELAY		20		/* 30 seconds */
	
	#define LONG_MAX_REQUEST_COUNT		40		/* 15 requests */
	#define LONG_MAX_REQUEST_DELAY		80		/* 30 seconds */
	
	#define SSHBAN_CHAIN	"sshbanner"
#endif
