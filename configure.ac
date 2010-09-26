AC_PREREQ(2.54)

AC_INIT([dovecot-antispam], [2.0.0], [eugene@raptor.kiev.ua])
AC_SUBST(PACKAGE, dovecot)

BUILDSYS_INIT
BUILDSYS_PROG_IMPLIB
BUILDSYS_SHARED_LIB

AC_PROG_CC
AC_PROG_CPP
AC_PROG_LN_S
AC_PROG_INSTALL

AC_CONFIG_SRCDIR(src)
AC_CONFIG_FILES([buildsys.mk extra.mk])
AC_CONFIG_HEADERS(config.h)

DC_DOVECOT

AC_MSG_CHECKING([for dovecot tree type])
if test x$LIBDOVECOT_STORAGE_DEPS != x; then
    AC_MSG_RESULT([build])
    AC_ERROR([Please install dovecot first and use that tree instead.])
fi
AC_MSG_RESULT([installed])

BUILDSYS_TOUCH_DEPS

AC_OUTPUT
