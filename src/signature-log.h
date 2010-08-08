#ifndef ANTISPAM_SIGNATURE_LOG_H
#define ANTISPAM_SIGNATURE_LOG_H

#include "lib.h"
#include "mail-user.h"
#include "mail-storage-private.h"

bool signature_log_init(struct mail_user *user, void **data);

void *signature_log_transaction_begin(struct mailbox *box,
	enum mailbox_transaction_flags flags);
int signature_log_transaction_commit(struct mailbox *box, void *data);
void signature_log_transaction_rollback(struct mailbox *box, void *data);
int signature_log_handle_mail(struct mailbox_transaction_context *t,
	void *data, struct mail *mail, bool spam);

#endif
