#include "lib.h"

#include "aux.h"

const char *config(struct mail_user *user, const char *suffix)
{
	const char *tmp;

	T_BEGIN
	{
		tmp = t_strconcat("antispam_", suffix, NULL);
		tmp = mail_user_plugin_getenv(user, tmp);
	}
	T_END;

	return tmp;
}

bool match_exact(const char *box_name, const char *query_name)
{
	return (null_strcmp(box_name, query_name) == 0);
}

bool match_pattern(const char *box_name, const char *query_name)
{
	size_t box_len = strlen(box_name);
	size_t query_len = strlen(query_name);

	if (query_len - 1 > box_len)
		// -1 is for possible asterisk in the end
		return FALSE;

	if (query_len && query_name[query_len - 1] == '*')
                query_len--;

	return (memcmp(box_name, query_name, query_len) == 0);
}

bool match_ipattern(const char *box_name, const char *query_name)
{
	bool ret;

	T_BEGIN
	{
		const char *bn = t_str_lcase(box_name);
		const char *qn = t_str_lcase(query_name);
		ret = match_pattern(bn, qn);
	}
	T_END;

	return ret;
}
