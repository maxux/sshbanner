#ifndef __SSHBAN_HANDLE_SSH_H
	#define __SSHBAN_HANDLE_SSH_H

	int ssh_handle(char *line, time_t timestamp, module_t *module);
	void __module_ssh_init();
#endif
