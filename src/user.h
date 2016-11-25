#ifndef ANTISPAM_USER_H
#define ANTISPAM_USER_H

#include "mail-user.h"
#include "module-context.h"

#include "aux.h"
#include "backends.h"

extern MODULE_CONTEXT_DEFINE(antispam_user_module, &mail_user_module_register);
#define USER_CONTEXT(obj) MODULE_CONTEXT(obj, antispam_user_module)

enum match_type
{
    MT_EXACT,
    MT_PATTERN,
    MT_PATTERN_IGNORE_CASE,

    /* should always be the last one */
    NUM_MT
};

typedef bool(*match_fn_t) (const char *box_name, const char *query_name);

static const struct
{
    const char *human;
    const char *suffix;
    match_fn_t fn;
} match_info[NUM_MT] =
{
    [MT_EXACT] =
    {
	.human = "exact match",
	.suffix = "",
	.fn = match_exact
    },
    [MT_PATTERN] =
    {
	.human = "wildcard match",
	.suffix = "_pattern",
	.fn = match_pattern
    },
    [MT_PATTERN_IGNORE_CASE] =
    {
	.human = "case-insensitive wildcard match",
	.suffix = "_pattern_ignorecase",
	.fn = match_ipattern
    }
};

struct antispam_user
{
    union mail_user_module_context module_ctx;

    // global config vars
    bool allow_append_to_spam;
    bool skip_from_line;

    char **folders_spam[NUM_MT];
    char **folders_trash[NUM_MT];
    char **folders_unsure[NUM_MT];

    char **flags_spam;

    // backend config vars pointer
    struct antispam_backend *backend;
    void *backend_config;
};

void antispam_user_created(struct mail_user *user);

#endif
