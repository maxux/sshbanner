#ifndef __SSHBAN_L_SSH_H
	#define __SSHBAN_L_SSH_H

	int lighttpd_handle(char *line, time_t timestamp, module_t *module);
	void __module_lighttpd_init();
#endif
