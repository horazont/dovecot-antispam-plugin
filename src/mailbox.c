#include "lib.h"

#include "user.h"
#include "mailbox.h"
#include "backends.h"

static MODULE_CONTEXT_DEFINE_INIT(antispam_storage_module,
	&mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(antispam_transaction_module,
	&mail_storage_module_register);

#define TRANSACTION_CONTEXT(obj) MODULE_CONTEXT(obj, antispam_transaction_module)

struct antispam_transaction
{
    union mailbox_transaction_module_context module_ctx;
    void *data;			// Backend specific data is stored here.
};

enum mailbox_copy_type
{
    MCT_IGNORE,
    MCT_SPAM,
    MCT_HAM,
    MCT_DENY
};

static enum mailbox_class antispam_mailbox_classify(struct mailbox *box)
{
    const char *name = mailbox_get_name(box);
    struct antispam_user *asu = USER_CONTEXT(box->storage->user);
    enum match_type i;
    char **iter;

#define CHECK(folders, class) \
    for (i = 0; i < NUM_MT; i++) \
    { \
	iter = asu->folders[i]; \
	if (!iter) \
	    continue; \
	while (*iter) \
	{ \
	    if (match_info[i].fn(name, *iter)) \
		return class; \
	    iter++; \
	} \
    }

    CHECK(folders_spam, CLASS_SPAM);
    CHECK(folders_trash, CLASS_TRASH);
    CHECK(folders_unsure, CLASS_UNSURE);

    return CLASS_OTHER;
#undef CHECK
}

static enum mailbox_copy_type antispam_classify_copy(enum mailbox_class src,
	enum mailbox_class dst)
{
    enum mailbox_copy_type ret = MCT_IGNORE;

#define DST(spam, trash, unsure, other) \
	switch (dst) { \
		case CLASS_SPAM: \
			ret = (spam); \
			break; \
		case CLASS_TRASH: \
			ret = (trash); \
			break; \
		case CLASS_UNSURE: \
			ret = (unsure); \
			break; \
		case CLASS_OTHER: \
			ret = (other); \
			break; \
	}

    switch (src)
    {
	case CLASS_SPAM:
	    DST(MCT_IGNORE, MCT_IGNORE, MCT_DENY, MCT_HAM);
	    break;
	case CLASS_TRASH:
	    DST(MCT_IGNORE, MCT_IGNORE, MCT_DENY, MCT_IGNORE);
	    break;
	case CLASS_UNSURE:
	    DST(MCT_SPAM, MCT_DENY, MCT_DENY, MCT_HAM);
	    break;
	case CLASS_OTHER:
	    DST(MCT_SPAM, MCT_IGNORE, MCT_DENY, MCT_IGNORE);
	    break;
    }

#undef DST

    return ret;
}

static int antispam_copy(struct mail_save_context *ctx, struct mail *mail)
{
    struct mailbox_transaction_context *t = ctx->transaction;
    struct antispam_mailbox *asmb = STORAGE_CONTEXT(t->box);
    struct antispam_mailbox *asms = STORAGE_CONTEXT(mail->box);
    struct antispam_transaction *ast = TRANSACTION_CONTEXT(t);
    struct antispam_user *asu = USER_CONTEXT(t->box->storage->user);

    enum mailbox_copy_type copy_type =
	    antispam_classify_copy(asms->box_class, asmb->box_class);

    switch (copy_type)
    {
	case MCT_HAM:
	case MCT_SPAM:
	    /* will continue processing further in this function */
	    break;
	case MCT_IGNORE:
	    return asmb->module_ctx.super.copy(ctx, mail);
	    break;
	case MCT_DENY:
	    mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		    "This type of copy is forbidden");
	    return -1;
	    break;
    }

    if (asmb->module_ctx.super.copy(ctx, mail) != 0)
	return -1;

    return asu->backend->handle_mail(t, ast->data, mail, copy_type == MCT_SPAM);
}

static int antispam_save_begin(struct mail_save_context *ctx,
	struct istream *input)
{
    struct mailbox_transaction_context *t = ctx->transaction;
    struct antispam_mailbox *asmb = STORAGE_CONTEXT(t->box);

    if (ctx->copying == 0)
    {
	struct antispam_user *asu = USER_CONTEXT(t->box->storage->user);

	// since there is no source mailbox, let's assume
	// we're saving from unclassified mailbox
	enum mailbox_copy_type copy_type =
		antispam_classify_copy(CLASS_OTHER, asmb->box_class);

	if (copy_type == MCT_SPAM && !asu->allow_append_to_spam)
	{
	    mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		    "APPENDing to spam folder is forbidden");
	    return -1;
	}

	if (copy_type == MCT_DENY)
	{
	    mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		    "This type of copy is forbidden");
	    return -1;
	}
    }

    return asmb->module_ctx.super.save_begin(ctx, input);
}

static int antispam_save_finish(struct mail_save_context *ctx)
{
    struct mailbox_transaction_context *t = ctx->transaction;
    struct antispam_mailbox *asmb = STORAGE_CONTEXT(t->box);
    struct antispam_transaction *ast = TRANSACTION_CONTEXT(t);
    struct antispam_user *asu = USER_CONTEXT(t->box->storage->user);

    // if we are copying then copy() code will do everything needed
    int ret = asmb->module_ctx.super.save_finish(ctx);
    if (ctx->copying != 0 || ret != 0)
	return ret;

    // since there is no source mailbox, let's assume
    // we're saving from unclassified mailbox
    enum mailbox_copy_type copy_type =
	    antispam_classify_copy(CLASS_OTHER, asmb->box_class);

    return copy_type == MCT_IGNORE ? 0 : asu->backend->handle_mail(t,
	    ast->data, ctx->dest_mail, copy_type == MCT_SPAM);
}

static struct mailbox_transaction_context *antispam_transaction_begin(struct
	mailbox *box, enum mailbox_transaction_flags flags)
{
    struct mailbox_transaction_context *ret;
    struct antispam_mailbox *asmb = STORAGE_CONTEXT(box);
    struct antispam_user *asu = USER_CONTEXT(box->storage->user);
    struct antispam_transaction *astr;

    ret = asmb->module_ctx.super.transaction_begin(box, flags);

    astr = i_new(struct antispam_transaction, 1);
    astr->data = asu->backend->transaction_begin(box, flags);

    MODULE_CONTEXT_SET(ret, antispam_transaction_module, astr);

    return ret;
}

static int antispam_transaction_commit(struct mailbox_transaction_context *t,
	struct mail_transaction_commit_changes *changes_r)
{
    int ret;
    struct mailbox *box = t->box;
    struct antispam_mailbox *asmb = STORAGE_CONTEXT(box);
    struct antispam_user *asu = USER_CONTEXT(box->storage->user);
    struct antispam_transaction *ast = TRANSACTION_CONTEXT(t);

    if ((ret = asmb->module_ctx.super.transaction_commit(t, changes_r)) != 0)
    {
	asu->backend->transaction_rollback(box, ast->data);
	i_free(ast);
	return ret;
    }

    ret = asu->backend->transaction_commit(box, ast->data);
    i_free(ast);
    return ret;
}

static void antispam_transaction_rollback(struct mailbox_transaction_context
	*t)
{
    struct antispam_mailbox *asmb = STORAGE_CONTEXT(t->box);
    struct antispam_user *asu = USER_CONTEXT(t->box->storage->user);
    struct antispam_transaction *ast = TRANSACTION_CONTEXT(t);

    asu->backend->transaction_rollback(t->box, ast->data);
    asmb->module_ctx.super.transaction_rollback(t);
    i_free(ast);
}

void antispam_mailbox_allocated(struct mailbox *box)
{
    struct antispam_mailbox *asmb;

    if (USER_CONTEXT(box->storage->user) == NULL)
	return;

    asmb = p_new(box->pool, struct antispam_mailbox, 1);
    asmb->module_ctx.super = box->v;

    asmb->box_class = antispam_mailbox_classify(box);

    box->v.copy = antispam_copy;
    box->v.save_begin = antispam_save_begin;
    box->v.save_finish = antispam_save_finish;
    box->v.transaction_begin = antispam_transaction_begin;
    box->v.transaction_commit = antispam_transaction_commit;
    box->v.transaction_rollback = antispam_transaction_rollback;

    MODULE_CONTEXT_SET(box, antispam_storage_module, asmb);
}
