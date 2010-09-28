NAME = dovecot-antispam
SECT = 7
MAN = ${NAME}.${SECT}
mansubdir = man${SECT}

CLEAN += ${MAN}

include ../buildsys.mk
include ../extra.mk

pre-depend: ${MAN}

${MAN}: ${MAN}.txt
	${COMPILE_STATUS}
	if ./txt2man -s 7 -r ${NAME} -t ${NAME} $< > $@; then \
	    ${COMPILE_OK}; \
	else \
	    ${COMPILE_FAILED}; \
	fi
	sed -i'' -e "s/\(antispam_[^ ,]*\)/\\\fI\1\\\fP/g" $@
