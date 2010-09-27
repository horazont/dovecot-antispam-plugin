#include "lib.h"

#include "backends.h"


#include "mailtrain.h"
#include "spool2dir.h"
#include "signature-log.h"
#include "dspam.h"
#define BACKENDS_COUNT 4

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
    REG_BACKEND(signature_log);
    REG_BACKEND(dspam);

#undef REG_BACKEND
}

struct antispam_backend *find_backend(const char *title)
{
    int i;

    for (i = 0; i < BACKENDS_COUNT; i++)
	if (strcasecmp(backends[i].title, title) == 0)
	    return &(backends[i]);

    return NULL;
}
