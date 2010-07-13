#ifndef ANTISPAM_PLUGIN_H
#define ANTISPAM_PLUGIN_H

#include "lib.h"
#include "mempool.h"
#include "module-dir.h"

extern pool_t global_pool;

void antispam_plugin_init(struct module *module);
void antispam_plugin_deinit(void);

#endif
