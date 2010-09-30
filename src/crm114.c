/*
 * crm114 backend for dovecot antispam plugin
 *
 * Copyright (C)      2010  Eugene Paskevich <eugene@raptor.kiev.ua>
 * Copyright (C) 2004-2007  Johannes Berg <johannes@sipsolutions.net>
 * Copyright (C)      2006  Frank Cusack
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

#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "lib.h"
#include "mail-user.h"
#include "mail-storage-private.h"

#include "aux.h"
#include "signature.h"
#include "user.h"

struct crm114_config
{
    const char *binary;
    const char *const *args;
    unsigned int args_num;
    const char *spam;
    const char *non_spam;

    void *sig_data;
};

static int call_reaver(struct mail_storage *storage, const char *signature,
	bool spam)
{
    struct antispam_user *asu = USER_CONTEXT(storage->user);
    struct crm114_config *cfg = asu->backend_config;
    int pipes[2];
    pid_t pid;

    /*
     * For reaver stdin, it wants to read a full message but
     * really only needs the signature.
     */
    if (pipe(pipes))
	return -1;

    pid = fork();
    if (pid < 0)
	return -1;

    if (pid)
    {
	int status;
	const char *signature_hdr = signature_header(cfg->sig_data);

	close(pipes[0]);

	// Reaver wants the mail but only needs the cache ID
	write(pipes[1], signature_hdr, strlen(signature_hdr));
	write(pipes[1], ": ", 2);
	write(pipes[1], signature, strlen(signature));
	write(pipes[1], "\r\n\r\n", 4);
	close(pipes[1]);

	/*
	 * Wait for reaver
	 */
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
	    return 1;

	return WEXITSTATUS(status);
    }
    else
    {
	/* 2 fixed, extra args, terminating NULL */
	int sz = sizeof(const char *) * (2 + cfg->args_num + 1);
	const char **argv = i_malloc(sz);
	int fd = open("/dev/null", O_RDONLY);
	int i = 0;
	int k = 0;

	close(0);
	close(1);
	close(2);
	/* see above */
	close(pipes[1]);

	if (dup2(pipes[0], 0) != 0)
	    exit(1);
	close(pipes[0]);

	if (dup2(fd, 1) != 1)
	    exit(1);
	if (dup2(fd, 2) != 2)
	    exit(1);
	close(fd);

	argv[i++] = cfg->binary;

	for (k = 0; k < cfg->args_num; k++)
	    argv[i++] = cfg->args[k];

	argv[i++] = spam ? cfg->spam : cfg->non_spam;

	execv(cfg->binary, (char *const *) argv);
	/* fall through if reaver can't be found */
	i_debug("executing %s failed: %d (uid=%d, gid=%d)", cfg->binary, errno,
		getuid(), getgid());
	exit(127);
	/* not reached */
	return -1;
    }
}

bool crm114_init(struct mail_user *user, void **data)
{
    struct crm114_config *cfg = p_new(user->pool, struct crm114_config, 1);
    const char *tmp;

    if (cfg == NULL)
	goto fail;

    cfg->binary = config(user, "crm_binary");
    if (EMPTY_STR(cfg->binary))
	cfg->binary = "/usr/share/crm114/mailreaver.crm";

    tmp = config(user, "crm_args");
    if (!EMPTY_STR(tmp))
    {
	cfg->args = (const char *const *) p_strsplit(user->pool, tmp, ";");
	cfg->args_num = str_array_length(cfg->args);
    }

    cfg->spam = config(user, "crm_spam");
    if (EMPTY_STR(cfg->spam))
	cfg->spam = "--spam";

    cfg->non_spam = config(user, "crm_notspam");
    if (EMPTY_STR(cfg->non_spam))
	cfg->non_spam = "--good";

    if (signature_init(user, &cfg->sig_data) == FALSE)
    {
	i_debug("failed to initialize the signature engine");
	p_free(user->pool, cfg);
	goto fail;
    }

    *data = cfg;
    return TRUE;

fail:
    *data = NULL;
    return FALSE;
}

struct crm114_transaction_context
{
    struct siglist *siglist;
};

void *crm114_transaction_begin(struct mailbox *box ATTR_UNUSED,
	enum mailbox_transaction_flags flags ATTR_UNUSED)
{
    return i_new(struct crm114_transaction_context, 1);
}

int crm114_transaction_commit(struct mailbox *box, void *data)
{
    struct crm114_transaction_context *ctc = data;
    struct siglist *item;
    int ret = 0;

    if (ctc == NULL)
    {
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Data allocation failed.");
	return -1;
    }

    item = ctc->siglist;

    while (item)
    {
	if (call_reaver(box->storage, item->sig, item->spam) != 0)
	{
	    ret = -1;
	    mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
		    "Failed to call crm114 binary");
	    break;
	}

	item = item->next;
    }

    signature_list_free(&ctc->siglist);
    i_free(ctc);
    return ret;
}

void crm114_transaction_rollback(struct mailbox *box ATTR_UNUSED, void *data)
{
    struct crm114_transaction_context *ctc = data;

    if (ctc == NULL)
	return;

    signature_list_free(&ctc->siglist);
    i_free(ctc);
}

int crm114_handle_mail(struct mailbox_transaction_context *t, void *data,
	struct mail *mail, bool spam)
{
    struct antispam_user *asu = USER_CONTEXT(t->box->storage->user);
    struct crm114_config *cfg = asu->backend_config;
    struct crm114_transaction_context *ctc = data;
    const char *result = NULL;
    const char *sig = NULL;

    if (ctc == NULL)
    {
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Data allocation failed.");
	return -1;
    }

    if (signature_extract(cfg->sig_data, mail, &sig) == -1)
    {
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Failed to extract the signature from the mail.");
	return -1;
    }

    signature_list_append(&ctc->siglist, sig, spam);
    return 0;
}
