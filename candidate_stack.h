#ifndef __SSHBAN_STACK_H
	#define __SSHBAN_STACK_H
	
	remote_t * stack_remote(remote_t **root, remote_t *new);
	remote_t * stack_search(remote_t *root, uint32_t ip);
	
	void stack_dump(remote_t *head);
#endif
