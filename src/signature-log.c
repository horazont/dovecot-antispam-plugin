/*
 * signature logging backend for dovecot antispam plugin
 *
 * Copyright (C) 2007       Johannes Berg <johannes@sipsolutions.net>
 * Copyright (C) 2010	    Eugene Paskevich <eugene@raptor.kiev.ua>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 */

/*
 * A training implementation must still be written, it needs, to be atomic,
 * use transactions to get a list of all values and delete them at the same
 * time, or use a temporary table that is copied from the original while the
 * original is emptied (again, atomically)
 */

/*
 * We really should have a global transaction as implemented
 * by the code that is commented out with C99 comments (//).
 * However, this breaks because
 * (1) sqlite cannot nest transactions
 * (2) the dict proxy keeps only a single connection open
 * (3) we here have a transaction per mailbox which makes two
 *     when moving messages (we might be able to hack around
 *     this but it's not trivial)
 */

#include "lib.h"
#include "dict.h"

#include "aux.h"
#include "signature-log.h"
#include "signature.h"
#include "user.h"


struct signature_log_config
{
    const char *base_dir;
    const char *dict_uri;
    const char *dict_user;
    void *sig_data;
};

bool signature_log_init(struct mail_user *user, void **data)
{
    struct signature_log_config *cfg =
	    p_new(user->pool, struct signature_log_config, 1);
    const char *tmp;

    if (cfg == NULL)
	goto fail;

    cfg->base_dir = mail_user_plugin_getenv(user, "base_dir");

    tmp = config(user, "siglog_dict_uri");
    if (EMPTY_STR(tmp))
    {
	i_debug("empty siglog_dict_uri");
	goto bailout;
    }
    cfg->dict_uri = tmp;

    tmp = config(user, "siglog_dict_user");
    if (EMPTY_STR(tmp))
    {
	i_debug("empty siglog_dict_user");
	goto bailout;
    }
    cfg->dict_user = tmp;

    if (signature_init(user, &cfg->sig_data) == FALSE)
    {
	i_debug("failed to initialize the signature engine");
	goto bailout;
    }

    *data = cfg;

    return TRUE;

bailout:
    p_free(user->pool, cfg);
fail:
    *data = NULL;
    return FALSE;
}

struct signature_log_transaction_context
{
    struct dict *dict;
    struct dict_transaction_context *dict_ctx;
};

void *signature_log_transaction_begin(struct mailbox *box,
	enum mailbox_transaction_flags flags ATTR_UNUSED)
{
    struct signature_log_transaction_context *sltc = NULL;
    struct antispam_user *asu = USER_CONTEXT(box->storage->user);
    struct signature_log_config *cfg = asu->backend_config;

    if (cfg == NULL)
	return NULL;

    sltc = i_new(struct signature_log_transaction_context, 1);

    if (sltc == NULL)
	return NULL;

    if (dict_init(cfg->dict_uri, DICT_DATA_TYPE_STRING, cfg->dict_user,
		cfg->base_dir, &sltc->dict, NULL))
    {
	i_free(sltc);
	return NULL;
    }

    //sltc->dict_ctx = dict_transaction_begin(sltc->dict); // see comment above

    return sltc;
}

int signature_log_transaction_commit(struct mailbox *box ATTR_UNUSED,
	void *data)
{
    struct signature_log_transaction_context *sltc = data;
    int ret = 0;

    if (sltc == NULL)
	return ret;

    if (sltc->dict != NULL)
    {
	// ret = dict_transaction_commit(&sltc->dict_ctx); // see comment above
	dict_deinit(&sltc->dict);
    }

    i_free(sltc);

    return ret;
}

void signature_log_transaction_rollback(struct mailbox *box ATTR_UNUSED,
	void *data)
{
    struct signature_log_transaction_context *sltc = data;

    if (sltc == NULL)
	return;

    if (sltc->dict != NULL)
    {
	//dict_transaction_rollback(&sltc->dict_ctx); // see comment above
	dict_deinit(&sltc->dict);
    }

    i_free(sltc);
}

int signature_log_handle_mail(struct mailbox_transaction_context *t,
	void *data, struct mail *mail, bool spam)
{
    struct signature_log_transaction_context *sltc = data;
    const char *signature;

    int ret = 0;

    if (sltc->dict == NULL)
    {
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Failed to initialise dict connection");
	return -1;
    }

    ret = signature_extract(t, mail, &signature);
    if (ret != 0)
    {
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Error retrieving signature header from the mail");
	return -1;
    }

    if (signature == NULL)
	return 0;

    T_BEGIN
    {
	const char *tmp = t_strconcat(DICT_PATH_PRIVATE, signature, NULL);
	const char *ex;

	ret = dict_lookup(sltc->dict, unsafe_data_stack_pool, tmp, &ex);

	sltc->dict_ctx = dict_transaction_begin(sltc->dict);
	if (ret == 0)
	    dict_set(sltc->dict_ctx, tmp, "0");
	dict_atomic_inc(sltc->dict_ctx, tmp, spam ? 1 : -1);
    }
    T_END;

    ret = dict_transaction_commit(&sltc->dict_ctx);

    if (ret == 1)
	return 0;

    if (ret == 0)
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Failed to add signature key");
    else
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Failed to increment signature value");

    return -1;
}
