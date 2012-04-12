#ifndef __SSHBAN_HANDLE_SSH_H
	#define __SSHBAN_HANDLE_SSH_H

	int ssh_handle(char *line, time_t timestamp);
	void ssh_unban(remote_t *head);
	
	extern char *ssh_rulz_append[2];
	extern char *ssh_rulz_delete[2];
#endif
