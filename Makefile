SUBDIRS = src doc

DISTCLEAN = buildsys.mk extra.mk config.h config.log config.status

include buildsys.mk
