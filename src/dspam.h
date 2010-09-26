#ifndef ANTISPAM_DSPAM_H
#define ANTISPAM_DSPAM_H

#include "lib.h"
#include "mail-user.h"
#include "mail-storage-private.h"

bool dspam_init(struct mail_user *user, void **data);

void *dspam_transaction_begin(struct mailbox *box,
	enum mailbox_transaction_flags flags);
int dspam_transaction_commit(struct mailbox *box, void *data);
void dspam_transaction_rollback(struct mailbox *box, void *data);
int dspam_handle_mail(struct mailbox_transaction_context *t, void *data,
	struct mail *mail, bool spam);

#endif
