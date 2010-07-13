#ifndef ANTISPAM_MAILBOX_H
#define ANTISPAM_MAILBOX_H

#include "lib.h"
#include "mail-storage.h"
#include "mail-storage-private.h"
#include "module-context.h"

#define STORAGE_CONTEXT(obj) MODULE_CONTEXT(obj, antispam_storage_module)

enum mailbox_class {
	CLASS_OTHER,
	CLASS_SPAM,
	CLASS_TRASH,
	CLASS_UNSURE
};

struct antispam_mailbox {
	union mailbox_module_context module_ctx;
	enum mailbox_class box_class;
};

void antispam_mailbox_allocated(struct mailbox *box);

#endif
