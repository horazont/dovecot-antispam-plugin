#ifndef ANTISPAM_SIGNATURE_H
#define ANTISPAM_SIGNATURE_H

#include "lib.h"
#include "mail-user.h"

struct siglist
{
    char *sig;
    bool spam;
    struct siglist *next;
};

bool signature_init(struct mail_user *user, void **data);

int signature_extract(void *data, struct mail *mail, const char **signature);
const char *signature_header(void *data);

void signature_list_append(struct siglist **list, const char *sig, bool spam);
void signature_list_free(struct siglist **list);

#endif
