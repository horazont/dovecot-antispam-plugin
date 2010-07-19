#include "lib.h"

#include "backends.h"


#include "mailtrain.h"
#include "spool2dir.h"
#define BACKENDS_COUNT 2

static struct antispam_backend backends[BACKENDS_COUNT];

void register_backends()
{
    int index = 0;

#define REG_BACKEND(name) \
	backends[index++] = (struct antispam_backend) { \
		#name, \
		name ## _init, \
		name ## _transaction_begin, \
		name ## _transaction_commit, \
		name ## _transaction_rollback, \
		name ## _handle_mail, \
	};

    REG_BACKEND(mailtrain);
    REG_BACKEND(spool2dir);

#undef REG_BACKEND
}

struct antispam_backend *find_backend(const char *title)
{
    int i;

    for (i = 0; i < BACKENDS_COUNT; i++)
	if (strcmp(backends[i].title, title) == 0)
	    return &(backends[i]);

    return NULL;
}
