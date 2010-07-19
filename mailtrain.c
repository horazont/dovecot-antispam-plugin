/*
 * mailing backend for dovecot antispam plugin
 *
 * Copyright (C) 2007       Johannes Berg <johannes@sipsolutions.net>
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

#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"

#include "aux.h"
#include "backends.h"
#include "mailbox.h"
#include "mailtrain.h"
#include "user.h"

struct mailtrain_config
{
    const char *binary;
    const char *const *args;
    bool skip_from;
    unsigned int args_num;
    const char *spam;
    const char *non_spam;
};

bool mailtrain_init(struct mail_user *user, void **data)
{
    struct mailtrain_config *cfg =
	    p_new(user->pool, struct mailtrain_config, 1);
    const char *tmp;

#define EMPTY_STR(arg) ((arg) == NULL || *(arg) == '\0')

    tmp = config(user, "mail_sendmail");
    if (EMPTY_STR(tmp))
    {
	i_debug("empty mail_sendmail");
	goto bailout;
    }
    cfg->binary = tmp;

    tmp = config(user, "mail_spam");
    if (EMPTY_STR(tmp))
    {
	i_debug("empty mail_spam");
	goto bailout;
    }
    cfg->spam = tmp;

    tmp = config(user, "mail_notspam");
    if (EMPTY_STR(tmp))
    {
	i_debug("empty mail_notspam");
	goto bailout;
    }
    cfg->non_spam = tmp;

    tmp = config(user, "mail_sendmail_args");
    if (!EMPTY_STR(tmp))
    {
	cfg->args = (const char *const *) p_strsplit(user->pool, tmp, ";");
	cfg->args_num = str_array_length(cfg->args);
    }

    tmp = config(user, "mail_skip_from");
    if (!EMPTY_STR(tmp) && strcasecmp(tmp, "yes") == 0)
	cfg->skip_from = TRUE;

#undef EMPTY_STR

    *data = cfg;

    return TRUE;

bailout:
    p_free(user->pool, cfg);
    *data = NULL;
    return FALSE;
}

struct mailtrain_transaction_context
{
    string_t *tmpdir;
    size_t tmplen;
    unsigned int messages;
};

static int run_sendmail(struct mail_storage *storage, int mailfd, bool spam)
{
    struct antispam_user *asu = USER_CONTEXT(storage->user);
    struct mailtrain_config *cfg = asu->backend_config;
    const char *dest = spam ? cfg->spam : cfg->non_spam;
    pid_t pid;
    int status;

    pid = fork();

    if (pid == -1)
    {
	mail_storage_set_error(storage, MAIL_ERROR_TEMP, "couldn't fork");
	return -1;
    }

    if (pid)
    {
	if (waitpid(pid, &status, 0) == -1)
	    return -1;
	if (!WIFEXITED(status))
	    return -1;
	return WEXITSTATUS(status);
    }
    else
    {
	int dnull = open("/dev/null", O_WRONLY);
	char **argv;
	int sz = sizeof(char *) * (1 + cfg->args_num + 1);
	unsigned int i;

	argv = i_new(char *, sz);
	argv[0] = (char *) cfg->binary;

	for (i = 0; i < cfg->args_num; i++)
	    argv[i + 1] = (char *) cfg->args[i];

	argv[i + 1] = (char *) dest;

#define DUP(fd, target) \
		if (dup2(fd, target) != target) \
		{ \
			mail_storage_set_error_from_errno(storage); \
			return -1; \
		}

	DUP(mailfd, 0);
	DUP(dnull, 1);
	DUP(dnull, 2);
#undef DUP

	execv(cfg->binary, argv);
	_exit(1);
	/* not reached */
	return -1;
    }
}

static int process_tmpdir(struct mailbox *box,
	struct mailtrain_transaction_context *mttc)
{
    unsigned int cnt = mttc->messages;
    int fd;
    bool spam;
    int rc = 0;

    while (rc == 0 && cnt > 0)
    {
	cnt--;
	str_printfa(mttc->tmpdir, "/%u", cnt);

	if ((fd = open(str_c(mttc->tmpdir), O_RDONLY)) == -1)
	{
	    mail_storage_set_error_from_errno(box->storage);
	    rc = -1;
	    break;
	}

	if (read(fd, &spam, sizeof(spam)) == -1)
	{
	    mail_storage_set_error_from_errno(box->storage);
	    rc = -1;
	    close(fd);
	    break;
	}

	str_truncate(mttc->tmpdir, mttc->tmplen);

	if (run_sendmail(box->storage, fd, spam) != 0)
	    rc = -1;

	close(fd);
    }

    str_truncate(mttc->tmpdir, mttc->tmplen);
    return rc;
}

static void clear_tmpdir(struct mailtrain_transaction_context *mttc)
{
    while (mttc->messages > 0)
    {
	mttc->messages--;
	str_printfa(mttc->tmpdir, "/%u", mttc->messages);
	unlink(str_c(mttc->tmpdir));
	str_truncate(mttc->tmpdir, mttc->tmplen);
    }

    rmdir(str_c(mttc->tmpdir));
}

void *mailtrain_transaction_begin(struct mailbox *box,
	enum mailbox_transaction_flags flags ATTR_UNUSED)
{
    struct mailtrain_transaction_context *mttc = NULL;

    mttc = i_new(struct mailtrain_transaction_context, 1);

    if (mttc == NULL)
	return NULL;

    mttc->messages = 0;

    mttc->tmpdir = str_new(default_pool, 0);
    if (mttc->tmpdir == NULL)
    {
	i_free(mttc);
	return NULL;
    }

    mail_user_set_get_temp_prefix(mttc->tmpdir, box->storage->user->set);
    str_append(mttc->tmpdir, "XXXXXX");

    mttc->tmplen = str_len(mttc->tmpdir);

    return mttc;
}

int mailtrain_transaction_commit(struct mailbox *box, void *data)
{
    struct mailtrain_transaction_context *mttc = data;
    int ret;

    if (mttc == NULL)
	return 0;

    if (mttc->tmpdir == NULL)
    {
	i_free(mttc);
	return 0;
    }

    ret = process_tmpdir(box, mttc);

    clear_tmpdir(mttc);

    str_free(&mttc->tmpdir);
    i_free(mttc);

    return ret;
}

void mailtrain_transaction_rollback(struct mailbox *box ATTR_UNUSED,
	void *data)
{
    struct mailtrain_transaction_context *mttc = data;

    if (mttc == NULL)
	return;

    if (mttc->tmpdir != NULL)
    {
	clear_tmpdir(mttc);
	str_free(&mttc->tmpdir);
    }

    i_free(mttc);
}

int mailtrain_handle_mail(struct mailbox_transaction_context *t, void *data,
	struct mail *mail, bool spam)
{
    struct mailtrain_transaction_context *mttc = data;
    struct antispam_user *asu = USER_CONTEXT(t->box->storage->user);
    struct istream *mailstream;
    struct ostream *outstream;
    int ret = 0;
    int fd;

    if (mttc == NULL)
    {
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Internal error during transaction initialization");
	return -1;
    }

    if (str_c(mttc->tmpdir)[mttc->tmplen - 1] == 'X'
	    && mkdtemp(str_c_modifiable(mttc->tmpdir)) == NULL)
    {
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Failed to initialize temporary dir");
	return -1;
    }

    if (mail_get_stream(mail, NULL, NULL, &mailstream) != 0)
    {
	mail_storage_set_error(t->box->storage, MAIL_ERROR_EXPUNGED,
		"Failed to get mail contents");
	return -1;
    }

    str_printfa(mttc->tmpdir, "/%u", mttc->messages);

    fd = creat(str_c(mttc->tmpdir), 0600);
    if (fd == -1)
    {
	mail_storage_set_error_from_errno(t->box->storage);
	ret = -1;
	goto out;
    }

    mttc->messages++;

    outstream = o_stream_create_fd(fd, 0, FALSE);
    if (!outstream)
    {
	ret = -1;
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Failed to stream temporary file");
	goto out_close;
    }

    if (o_stream_send(outstream, &spam, sizeof(spam)) != sizeof(spam))
    {
	ret = -1;
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Failed to write marker to temp file");
	goto failed_to_copy;
    }

    if (asu->skip_from_line == TRUE)
    {
	const unsigned char *beginning;
	size_t size;

	if (i_stream_read_data(mailstream, &beginning, &size, 5) < 0
		|| size < 5)
	{
	    ret = -1;
	    mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		    "Failed to read mail beginning");
	    goto failed_to_copy;
	}

	if (memcmp("From ", beginning, 5) == 0)
	    i_stream_read_next_line(mailstream);
	else
	    o_stream_send(outstream, &beginning, 5);
    }

    if (o_stream_send_istream(outstream, mailstream) < 0)
    {
	ret = -1;
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Failed to copy to temporary file");
	goto failed_to_copy;
    }

failed_to_copy:
    o_stream_destroy(&outstream);
out_close:
    close(fd);
out:

    str_truncate(mttc->tmpdir, mttc->tmplen);

    return ret;
}
