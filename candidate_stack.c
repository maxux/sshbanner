#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include "banner.h"
#include "candidate_stack.h"

extern system_t sys;

remote_t * stack_remote(remote_t *new) {
	new->next = sys.candidate;
	sys.candidate = new;
	
	return new;
}

remote_t * stack_search(uint32_t ip) {
	remote_t *temp;
	
	temp = sys.candidate;
	while(temp && temp->ip != ip)
		temp = temp->next;
		
	return temp;
}

void stack_dump(remote_t *head) {
	remote_t *temp = head;
	
	while(temp) {
		printf("[ ] IP    : %u\n", temp->ip);
		printf("[ ] First : %u\n", (unsigned int) temp->first);
		printf("[ ] Last  : %u\n", (unsigned int) temp->last);
		printf("[ ] Hits  : %d\n", temp->nbrequest);
		
		temp = temp->next;
	}
}
