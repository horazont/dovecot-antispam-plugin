#include <stdlib.h>

#include "lib.h"
#include "mail-storage.h"
#include "mail-user.h"

#include "aux.h"
#include "signature.h"

struct signature_data
{
    const char *header;
    bool ignore_missing;
};

bool signature_init(struct mail_user *user, void **data)
{
    struct signature_data *cfg = p_new(user->pool, struct signature_data, 1);
    const char *tmp;

    if (cfg == NULL)
	goto fail;

    tmp = config(user, "signature");
    if (EMPTY_STR(tmp))
    {
	i_debug("empty signature");
	goto bailout;
    }
    cfg->header = tmp;

    tmp = config(user, "signature_missing");
    if (EMPTY_STR(tmp))
	cfg->ignore_missing = FALSE;
    else
    {
	if (strcasecmp(tmp, "move") == 0)
	    cfg->ignore_missing = TRUE;
	else if (strcasecmp(tmp, "error") != 0)
	{
	    i_debug("invalid value for signature_missing");
	    goto bailout;
	}
    }

    *data = cfg;
    return TRUE;

bailout:
    p_free(user->pool, cfg);
fail:
    *data = NULL;
    return FALSE;
}

int signature_extract(void *data, struct mail *mail, const char **signature)
{
    struct signature_data *cfg = data;
    const char *const *signatures = NULL;
    int ret;

    *signature = NULL;

    ret = mail_get_headers_utf8(mail, cfg->header, &signatures);

    if (ret < 0)
	return cfg->ignore_missing == TRUE ? 0 : -1;

    while (signatures[1])
	signatures++;

    *signature = signatures[0];

    return 0;
}

const char *signature_header(void *data)
{
    struct signature_data *cfg = data;

    return cfg->header;
}

void signature_list_append(struct siglist **list, const char *sig, bool spam)
{
    struct siglist *ptr;

    if (list == NULL || sig == NULL)
	return;

    if (*list == NULL)
    {
	*list = i_new(struct siglist, 1);
	i_assert(*list != NULL);
    }
    ptr = *list;

    while (ptr->next != NULL)
	ptr = ptr->next;

    if (ptr->sig != NULL)
    {
	ptr = ptr->next = i_new(struct siglist, 1);
	i_assert(ptr != NULL);
    }

    ptr->sig = i_strdup(sig);
    ptr->spam = spam;
    i_assert(ptr->sig != NULL);
}

void signature_list_free(struct siglist **list)
{
    struct siglist *item;
    struct siglist *next;

    if (list == NULL || *list == NULL)
	return;

    item = *list;

    while (item)
    {
	next = item->next;

	i_free(item->sig);
	i_free(item);

	item = next;
    }
}
