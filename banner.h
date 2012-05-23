#ifndef __FWLBAN_BANNING_H
	#define __FWLBAN_BANNING_H
	
	int  fwlban_ban(remote_t *remote, module_t *module);
	
	void fwlban_unban(remote_t *remote, module_t *module);
	void fwlban_unban_all(module_t *modules);
#endif
