#ifndef ANTISPAM_AUX_H
#define ANTISPAM_AUX_H

#include "mail-user.h"

const char *config(struct mail_user *user, const char *suffix);
bool match_exact(const char *box_name, const char *query_name);
bool match_pattern(const char *box_name, const char *query_name);
bool match_ipattern(const char *box_name, const char *query_name);

#endif
