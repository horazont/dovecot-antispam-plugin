#ifndef ANTISPAM_PLUGIN_H
#define ANTISPAM_PLUGIN_H

#include "lib.h"
#include "module-dir.h"

void antispam_plugin_init(struct module *module);
void antispam_plugin_deinit(void);

#endif
