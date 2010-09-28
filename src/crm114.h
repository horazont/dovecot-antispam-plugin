#ifndef ANTISPAM_CRM114_H
#define ANTISPAM_CRM114_H

#include "lib.h"
#include "mail-user.h"
#include "mail-storage-private.h"

bool crm114_init(struct mail_user *user, void **data);

void *crm114_transaction_begin(struct mailbox *box,
	enum mailbox_transaction_flags flags);
int crm114_transaction_commit(struct mailbox *box, void *data);
void crm114_transaction_rollback(struct mailbox *box, void *data);
int crm114_handle_mail(struct mailbox_transaction_context *t, void *data,
	struct mail *mail, bool spam);

#endif
