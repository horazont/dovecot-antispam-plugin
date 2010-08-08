#ifndef ANTISPAM_SIGNATURE_H
#define ANTISPAM_SIGNATURE_H

struct siglist
{
    const char *sig;
    bool spam;
    struct siglist *next;
};

bool signature_init(mail_user *user, void **data);

int signature_extract(void *data, struct mail *mail, const char **signature);

void signature_list_append(struct siglist *list, const char *sig, bool spam);
void signature_list_free(struct siglist **list);

#endif
