#ifndef ANTISPAM_SPOOL2DIR_H
#define ANTISPAM_SPOOL2DIR_H

#include "lib.h"
#include "mail-user.h"
#include "mail-storage-private.h"

bool spool2dir_init(struct mail_user *user, void **data);

void *spool2dir_transaction_begin(struct mailbox *box,
	enum mailbox_transaction_flags flags);
int spool2dir_transaction_commit(struct mailbox *box, void *data);
void spool2dir_transaction_rollback(struct mailbox *box, void *data);
int spool2dir_handle_mail(struct mailbox_transaction_context *t, void *data,
	struct mail *mail, bool spam);

#endif
