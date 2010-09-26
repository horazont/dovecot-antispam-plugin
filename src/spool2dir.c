/*
 * mailing backend for dovecot antispam plugin
 *
 * Copyright (C) 2008       Steffen Kaiser <skdovecot@smail.inf.fh-brs.de>
 * this backend "spool2dir" bases on "mailtrain" backend of
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
 * along with this program; if not, write to the
 * Free Software Foundation, Inc.,
 * 51, Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */


/*
 * spool2dir antispam backend / plugin
 *
 * Any modification of SPAM status is recorded into a directory.
 *
 * Configuration
 *
 * Via settings similiar to the other antispam backends
 *	antispam_spool2dir_spam :- filename template for SPAM messages
 *	antispam_spool2dir_notsam :- filename template for HAM messages
 *
 * The templates _must_ provide two arguments:
 *   1. %%lu - the current unix time (lowercase L, lowercase U)
 *   2. %%lu - a counter to create different temporary files
 * Note: The %-sign must be given two times to protect against
 *  the expansion by Dovecot itself. You can put any legal
 *  format modification character of C's printf() function between
 *  '%%' and 'lu'.
 *
 * e.g.:
 *	antispam_spool2dir_spam = /tmp/spamspool/%%020lu-%%05lu-%u-S
 *	antispam_spool2dir_ham  = /tmp/spamspool/%%020lu-%%05lu-%u-H
 *
 * This example will spool the messages into the directory
 * /tmp/spamspool. The individual files start with 20 digits,
 * followed by a dash, 5 digits, the current username and S or H,
 * indicating Spam or Ham messages.
 * The first %%lu placeholder is replace by the current unix time,
 * the second %%lu with the counter. That way, if the same user
 * trains the same message twice, the filename indicates the order
 * in which it was done. So if the message was trained as SPAM first,
 * as HAM later, HAM supersedes SPAM.
 *
 * Operation
 *
 * When the antispam plugin identifies detects a SPAM status change,
 * e.g. moving/copying a message from any antispam_spam folder into
 * a folder _not_ listed in antispam_spam or antispam_trash, this
 * backend spools the complete message into antispam_mail_basedir.
 * If there is an error copying _all_ messages around, old spools
 * are kept, but the current one is deleted. For instance, if the
 * user is copying 15 messages, but only 10 succeed, the 10 would
 * be usually deleted. In this backend there is no rollback of
 * successfully spooled message, only the failed message is
 * deleted.
 *
 * Possible usage models
 *
 * A)
 *   I use spool2dir for training the Bayes database as follows:
 *
 *   Every 10 seconds a service invokes the training program, unless
 *   it already runs.
 *
 *   The training program reads the content of the spool directory, sorts
 *   the filenames alphanumerically, waits two seconds to allow any current
 *   spool2dir processes to finish currently open files.
 *   Then one message at a time is read and identified, if it contains
 *   local modifications, e.g. user-visible SPAM reports, which are removed.
 *   Furthermore, reports of untrustworthy people are discarded.
 *   This process continues until either all messages are processed or
 *   the next message would have another SPAM report type (HAM or SPAM). The
 *   file names of the messages processed till now are passed to the Bayes
 *   trainer to be processed within one run. Then those messages are removed.
 *
 * B)
 *
 *   An Inotify server watches the spamspool directory and passes the messages
 *   to spamd. No need for the filenames to indicate the order anymore, unless
 *   the inotify server is not fast enough.
 */

#include "lib.h"
#include "aux.h"
#include "user.h"

#include "ostream.h"
#include "istream.h"

#include "spool2dir.h"

struct spool2dir_config
{
    const char *spam;
    const char *ham;
};

struct spool2dir_transaction_context
{
    unsigned long count;
};

bool spool2dir_init(struct mail_user *user, void **data)
{
    struct spool2dir_config *cfg;
    const char *tmp;

    cfg = p_new(user->pool, struct spool2dir_config, 1);

    if (cfg == NULL)
	goto fail;

    tmp = config(user, "spool2dir_spam");
    if (EMPTY_STR(tmp))
    {
	i_debug("empty spool2dir_spam");
	goto bailout;
    }
    cfg->spam = tmp;

    tmp = config(user, "spool2dir_notspam");
    if (EMPTY_STR(tmp))
    {
	i_debug("empty spool2dir_notspam");
	goto bailout;
    }
    cfg->ham = tmp;

    *data = cfg;

    return TRUE;

bailout:
    p_free(user->pool, cfg);
fail:
    *data = NULL;
    return FALSE;
}


void *spool2dir_transaction_begin(struct mailbox *box ATTR_UNUSED,
	enum mailbox_transaction_flags flags ATTR_UNUSED)
{
    struct spool2dir_transaction_context *s2dtc;

    s2dtc = i_new(struct spool2dir_transaction_context, 1);
    if (s2dtc == NULL)
	return NULL;

    s2dtc->count = 0UL;

    return s2dtc;
}

int spool2dir_transaction_commit(struct mailbox *box ATTR_UNUSED, void *data)
{
    struct spool2dir_transaction_context *s2dtc = data;

    i_free(s2dtc);

    return 0;
}

void spool2dir_transaction_rollback(struct mailbox *box ATTR_UNUSED,
	void *data)
{
    struct spool2dir_transaction_context *s2dtc = data;

    i_free(s2dtc);
}

int spool2dir_handle_mail(struct mailbox_transaction_context *t, void *data,
	struct mail *mail, bool spam)
{
    struct spool2dir_transaction_context *s2dtc = data;
    struct antispam_user *asu = USER_CONTEXT(t->box->storage->user);
    struct spool2dir_config *cfg = asu->backend_config;
    const char *dest = spam ? cfg->spam : cfg->ham;

    struct istream *mailstream;
    struct ostream *outstream;
    int ret = 0;
    char *file = NULL;
    int fd;

    if (s2dtc == NULL)
    {
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Internal error during transaction initialization");
	return -1;
    }

    if (mail_get_stream(mail, NULL, NULL, &mailstream) != 0)
    {
	mail_storage_set_error(t->box->storage, MAIL_ERROR_EXPUNGED,
		"Failed to get mail contents");
	return -1;
    }

    /* atomically create a _new_ file */
    while (s2dtc->count <= ULONG_MAX)
    {
	file = i_strdup_printf(dest, (unsigned long) time(NULL),
		++s2dtc->count);
	fd = open(file, O_CREAT | O_EXCL | O_WRONLY, 0600);
	if (fd != -1 || errno != EEXIST)
	    break;
	/* current filename already exists, zap it */
	i_free(file);
	file = NULL;
    }

    if (fd < 0)
    {
	mail_storage_set_error_from_errno(t->box->storage);
	ret = -1;
	goto out;
    }

    /* buf still points to allocated memory, because fd != -1 */
    outstream = o_stream_create_fd(fd, 0, FALSE);
    if (!outstream)
    {
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Failed to stream spool file");
	ret = -1;
	goto out_close;
    }

    if (asu->skip_from_line == TRUE)
    {
	const unsigned char *beginning;
	size_t size;

	if (i_stream_read_data(mailstream, &beginning, &size, 5) < 0
		|| size < 5)
	{
	    mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		    "Failed to read mail beginning");
	    ret = -1;
	    goto failed_to_copy;
	}

	if (memcmp("From ", beginning, 5) == 0)
	    i_stream_read_next_line(mailstream);
	else
	    o_stream_send(outstream, &beginning, 5);
    }

    if (o_stream_send_istream(outstream, mailstream) < 0)
    {
	mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE,
		"Failed to copy to spool file");
	ret = -1;
	goto failed_to_copy;
    }

failed_to_copy:
    o_stream_destroy(&outstream);

out_close:
    close(fd);

    if (ret == -1 && file != NULL)
	unlink(file);

out:
    if (file != NULL)
	i_free(file);

    return ret;
}
