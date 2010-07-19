#ifndef ANTISPAM_BACKENDS_H
#define ANTISPAM_BACKENDS_H

#include "lib.h"
#include "mail-storage.h"
#include "mail-storage-private.h"

typedef bool(*init_fn_t) (struct mail_user *, void **);
typedef void *(*transaction_begin_fn_t) (struct mailbox *,
	enum mailbox_transaction_flags);
typedef int (*transaction_commit_fn_t) (struct mailbox *, void *);
typedef void (*transaction_rollback_fn_t) (struct mailbox *, void *);
typedef int (*handle_mail_fn_t) (struct mailbox_transaction_context *, void *,
	struct mail *, bool);

struct antispam_backend
{
    char *title;
    init_fn_t init;
    transaction_begin_fn_t transaction_begin;
    transaction_commit_fn_t transaction_commit;
    transaction_rollback_fn_t transaction_rollback;
    handle_mail_fn_t handle_mail;
};

void register_backends(void);
struct antispam_backend *find_backend(const char *title);

#endif
