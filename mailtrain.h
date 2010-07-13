#ifndef ANTISPAM_MAILTRAIN_H
#define ANTISPAM_MAILTRAIN_H

#include "lib.h"
#include "mail-user.h"
#include "mail-storage-private.h"

bool mailtrain_init(struct mail_user *user, void **data);

void *mailtrain_transaction_begin(struct mailbox *box,
		enum mailbox_transaction_flags flags);
int mailtrain_transaction_commit(struct mailbox *box,
		void *data);
void mailtrain_transaction_rollback(struct mailbox *box,
		void *data);
int mailtrain_handle_mail(struct mailbox_transaction_context *t,
		void *data,
		struct mail *mail,
		bool spam);

#endif
