/*
 * dspam backend for dovecot antispam plugin
 *
 * Copyright (C) 2010	    Eugene Paskevich <eugene@raptor.kiev.ua>
 * Copyright (C) 2004-2007  Johannes Berg <johannes@sipsolutions.net>
 * Copyright (C) 2006	    Frank Cusack
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

struct dspam_config
{
    const char *binary;
    const char *const *args;
    unsigned int args_num;
    const char *spam;
    const char *non_spam;

    const char *result_hdr;
    const char *const *result_bl;
    unsigned int result_bl_num;

    void *sig_data;
};

static int call_dspam(struct mail_storage *storage, const char *sig, bool spam)
{
    int pipes[2];
    pid_t pid;

    /*
     * For dspam stderr; dspam seems to not always exit with a
     * non-zero exit code on errors so we treat it as an error
     * if it logged anything to stderr.
     */
    if (pipe(pipes) < 0)
	return -1;

    pid = fork();
    if (pid < 0)
	return -1;

    if (pid)
    {
	int status;
	char buf[1025];
	int readsize;
	bool error = FALSE;

	close(pipes[1]);

	do
	{
	    readsize = read(pipes[0], buf, sizeof(buf) - 1);
	    if (readsize < 0)
	    {
		readsize = -1;
		if (errno == EINTR)
		    readsize = -2;
	    }

	    /*
	     * readsize > 0 means that we read a message from
	     * dspam, -1 means we failed to read for some odd
	     * reason
	     */
	    if (readsize > 0 || readsize == -1)
		error = TRUE;

	    if (readsize > 0)
	    {
		buf[readsize] = '\0';
		i_debug("dspam error: %s\n", buf);
	    }
	}
	while (readsize == -2 || readsize > 0);

	/*
	 * Wait for dspam, should return instantly since we've
	 * already waited above (waiting for stderr to close)
	 */
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status))
	    error = TRUE;

	close(pipes[0]);
	if (error)
	    return 1;
	return WEXITSTATUS(status);
    }
    else
    {
	struct antispam_user *asu = USER_CONTEXT(storage->user);
	struct dspam_config *cfg = asu->backend_config;

	/* 2 fixed arg, extra args, terminating NULL */
	int sz = sizeof(const char *) * (2 + cfg->args_num + 1);
	const char **argv = i_malloc(sz);

	int fd = open("/dev/null", O_RDONLY);
	int i = 0, k = 0;

	close(0);
	close(1);
	close(2);
	/* see above */
	close(pipes[0]);

	if (dup2(pipes[1], 2) != 2)
	    exit(1);
	if (dup2(pipes[1], 1) != 1)
	    exit(1);
	close(pipes[1]);

	if (dup2(fd, 0) != 0)
	    exit(1);
	close(fd);

	argv[i++] = cfg->binary;

	for (k = 0; k < cfg->args_num; k++)
	    if (strstr(cfg->args[k], "%s"))
		argv[i++] = t_strdup_printf(cfg->args[k], sig);
	    else
		argv[i++] = cfg->args[k];

	argv[i++] = spam ? cfg->spam : cfg->non_spam;

	execv(cfg->binary, (char * const *) argv);
	i_debug("executing %s failed: %d (uid=%d, gid=%d)", cfg->binary, errno,
		getuid(), getgid());
	/* fall through if dspam can't be found */
	exit(127);
	/* not reached */
	return -1;
    }
}

bool dspam_init(struct mail_user *user, void **data)
{
    struct dspam_config *cfg = p_new(user->pool, struct dspam_config, 1);
    const char *tmp;

    if (cfg == NULL)
	goto fail;

    cfg->binary = config(user, "dspam_binary");
    if (EMPTY_STR(cfg->binary))
	cfg->binary = "/usr/bin/dspam";

    tmp = config(user, "dspam_args");
    if (EMPTY_STR(tmp))
	tmp = "--source=error;--signature=%s";

    cfg->args = (const char *const *) p_strsplit(user->pool, tmp, ";");
    cfg->args_num = str_array_length(cfg->args);

    cfg->spam = config(user, "dspam_spam");
    if (EMPTY_STR(cfg->spam))
	cfg->spam = "--class=spam";

    cfg->non_spam = config(user, "dspam_notspam");
    if (EMPTY_STR(cfg->non_spam))
	cfg->non_spam = "--class=innocent";

    cfg->result_hdr = config(user, "dspam_result_header");
    if (!EMPTY_STR(cfg->result_hdr))
    {
	tmp = config(user, "dspam_result_blacklist");
	if (!EMPTY_STR(tmp))
	{
	    cfg->result_bl =
		(const char *const *) p_strsplit(user->pool, tmp, ";");
	    cfg->result_bl_num = str_array_length(cfg->result_bl);
	}
    }

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

struct dspam_transaction_context
{
    struct siglist *siglist;
};

void *dspam_transaction_begin(struct mailbox *box ATTR_UNUSED,
	enum mailbox_transaction_flags flags ATTR_UNUSED)
{
    return i_new(struct dspam_transaction_context, 1);
}

int dspam_transaction_commit(struct mailbox *box, void *data)
{
    struct dspam_transaction_context *dtc = data;
    struct siglist *item;
    int ret = 0;

    if (dtc == NULL)
    {
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Data allocation failed.");
	return -1;
    }

    item = dtc->siglist;

    while (item)
    {
	if (call_dspam(box->storage, item->sig, item->spam) != 0)
	{
	    ret = -1;
	    mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
		    "Failed to call dspam");
	    break;
	}

	item = item->next;
    }

    signature_list_free(&dtc->siglist);
    i_free(dtc);
    return ret;
}

void dspam_transaction_rollback(struct mailbox *box ATTR_UNUSED, void *data)
{
    struct dspam_transaction_context *dtc = data;

    if (dtc == NULL)
	return;

    signature_list_free(&dtc->siglist);
    i_free(dtc);
}

int dspam_handle_mail(struct mailbox_transaction_context *t, void *data,
	struct mail *mail, bool spam)
{
    struct antispam_user *asu = USER_CONTEXT(t->box->storage->user);
    struct dspam_config *cfg = asu->backend_config;
    struct dspam_transaction_context *dtc = data;
    const char *result = NULL;
    const char *sig = NULL;

    if (dtc == NULL)
    {
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Data allocation failed.");
	return -1;
    }

    /*
     * Check for blacklisted classifications that should
     * be ignored when moving a mail. eg. virus.
     */
    if (cfg->result_hdr != NULL
	    && mail_get_first_header(mail, cfg->result_hdr, &result) == 1)
    {
	int i;

	for (i = 0; i < cfg->result_bl_num; i++)
	{
	    if (strcasecmp(result, cfg->result_bl[i]) == 0)
		return 0;
	}
    }

    if (signature_extract(cfg->sig_data, mail, &sig) == -1)
    {
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Failed to extract the signature from the mail.");
	return -1;
    }

    signature_list_append(&dtc->siglist, sig, spam);
    return 0;
}
