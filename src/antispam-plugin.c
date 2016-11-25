#include "lib.h"
#include "mail-storage-hooks.h"
#include "notify-plugin.h"

#include "antispam-plugin.h"
#include "user.h"
#include "mailbox.h"
#include "backends.h"

static struct mail_storage_hooks antispam_plugin_hooks = {
    .mail_user_created = antispam_user_created,
    .mail_allocated = antispam_mail_allocated,
    .mailbox_allocated = antispam_mailbox_allocated
};

void antispam_plugin_init(struct module *module)
{
    register_backends();

    mail_storage_hooks_add(module, &antispam_plugin_hooks);
}

void antispam_plugin_deinit(void)
{
    mail_storage_hooks_remove(&antispam_plugin_hooks);
}

#ifdef DOVECOT_ABI_VERSION
const char *antispam_plugin_version = DOVECOT_ABI_VERSION;
#else
const char *antispam_plugin_version = DOVECOT_VERSION;
#endif
