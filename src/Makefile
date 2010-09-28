SRCS = \
       antispam-plugin.c \
       aux.c \
       backends.c \
       crm114.c \
       dspam.c \
       mailbox.c \
       mailtrain.c \
       signature-log.c \
       signature.c \
       spool2dir.c \
       user.c

PLUGIN = lib90_antispam_plugin${PLUGIN_SUFFIX}

include ../buildsys.mk
include ../extra.mk

CPPFLAGS += ${DEFS} ${DOVECOT_INCLUDE} ${DOVECOT_STORAGE_INCLUDE} -I.
CFLAGS += ${PLUGIN_CFLAGS}
LDFLAGS += ${PLUGIN_LDFLAGS} ${DOVECOT_LIB} ${DOVECOT_STORAGE_LIB}

plugindir = ${DOVECOT_MODULE_DIR}
