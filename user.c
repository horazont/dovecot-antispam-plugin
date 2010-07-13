#include "lib.h"

#include "user.h"
#include "aux.h"
#include "antispam-plugin.h"

struct antispam_user_module antispam_user_module = \
	MODULE_CONTEXT_INIT(&mail_user_module_register);

static void parse_folders(struct mail_user *user, const char *infix, char ***result)
{
	const char *tmp;
	enum match_type i;

	T_BEGIN
	{
		for (i = 0; i < NUM_MT; i++)
		{
			tmp = t_strconcat(infix, match_info[i].suffix, NULL);
			tmp = config(user, tmp);
			if (tmp)
				result[i] = p_strsplit(global_pool, tmp, ";");
		}
	}
	T_END;
}

static bool check_folders(char ***folders)
{
	int i;
	bool ret = FALSE;

	if (folders == NULL)
		return FALSE;

	for (i = 0; i < NUM_MT; i++)
	{
		if (folders[i] == NULL || folders[i][0] == NULL)
			continue;
		else
			if (folders[i][0][0] == '\0')
				continue;
			else
			{
				ret = TRUE;
				break;
			}
	}

	return ret;
}

void antispam_user_created(struct mail_user *user)
{
	struct antispam_user *asu;
	const char *tmp;

	asu = p_new(global_pool, struct antispam_user, 1);
	asu->module_ctx.super = user->v;

	/* Read the global configuration */
#define EMPTY_STR(arg) ((arg) == NULL || *(arg) == '\0')

	tmp = config(user, "backend");
	if (EMPTY_STR(tmp))
	{
		i_error("antispam plugin backend is not selected for this user");
		goto bailout;
	}
	asu->backend = find_backend(tmp);
	if (asu->backend == NULL)
	{
		i_error("configured non-existent antispam backend: '%s'", tmp);
		goto bailout;
	}
	if (!asu->backend->init(user, &(asu->backend_config)))
		goto bailout;

	tmp = config(user, "allow_append_to_spam");
	if (!EMPTY_STR(tmp) && strcasecmp(tmp, "yes") == 0)
		asu->allow_append_to_spam = TRUE;

	tmp = config(user, "skip_from_line");
	if (!EMPTY_STR(tmp) && strcasecmp(tmp, "yes") == 0)
		asu->skip_from_line = TRUE;

	parse_folders(user, "spam", asu->folders_spam);
	parse_folders(user, "trash", asu->folders_trash);
	parse_folders(user, "unsure", asu->folders_unsure);

	if (!(check_folders(asu->folders_spam) ||
	      check_folders(asu->folders_trash) ||
	      check_folders(asu->folders_unsure)))
	{
		i_error("antispam plugin folders are not configured for this user");
		goto bailout;
	}

	MODULE_CONTEXT_SET(user, antispam_user_module, asu);
#undef EMPTY_STR
	return;
bailout:
	p_free(global_pool, asu);
}
