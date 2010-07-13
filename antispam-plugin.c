#include "lib.h"
#include "mail-storage-hooks.h"

#include "antispam-plugin.h"
#include "user.h"
#include "mailbox.h"
#include "backends.h"

pool_t global_pool;

static struct mail_storage_hooks antispam_plugin_hooks = {
	.mail_user_created = antispam_user_created,
	.mailbox_allocated = antispam_mailbox_allocated
};

void antispam_plugin_init(struct module *module)
{
	global_pool = pool_alloconly_create("antispam-pool", 1024);

	register_backends();

	mail_storage_hooks_add(module, &antispam_plugin_hooks);
}

void antispam_plugin_deinit(void)
{
	mail_storage_hooks_remove(&antispam_plugin_hooks);

	pool_unref(&global_pool);
}

const char *antispam_plugin_version = DOVECOT_VERSION;
