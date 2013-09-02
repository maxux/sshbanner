#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include "fwlban.h"
#include "candidate_stack.h"

remote_t * stack_remote(remote_t **root, remote_t *new) {
	new->next = *root;
	*root = new;
	
	return new;
}

remote_t * stack_search(remote_t *root, uint32_t ip) {
	remote_t *temp;
	
	temp = root;
	while(temp && temp->ip != ip)
		temp = temp->next;
		
	return temp;
}

void stack_dump(remote_t *head) {
	while(head) {
		printf("[ ] Stack: ip/first/last/Hits: %u / %u / %u / %zu\n",
		       head->ip, (unsigned int) head->first, (unsigned int) head->last,
		       head->nbrequest);

		head = head->next;
	}
}
