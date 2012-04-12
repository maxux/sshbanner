#ifndef __SSHBAN_STACK_H
	#define __SSHBAN_STACK_H
	
	remote_t * stack_remote(remote_t *new);
	remote_t * stack_search(uint32_t ip);
	
	void stack_dump(remote_t *head);
#endif
