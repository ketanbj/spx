
AC_INIT([noise-c], [0.0.1])
AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_RANLIB
AC_PROG_LEX
AC_PROG_YACC
AC_PATH_PROG(DOXYGEN, doxygen)

dnl Determine the default Ed448-Goldilocks architecture to use.
AC_CHECK_DECL([__x86_64__])
AC_CHECK_SIZEOF(void *)
if test "x$ac_cv_have_decl___x86_64__" = "xyes" ; then
    ED448_DEFAULT_ARCH=arch_x86_64
else
    if test "x$ac_cv_sizeof_void_p" = "x8" ; then
        ED448_DEFAULT_ARCH=arch_ref64
    else
        ED448_DEFAULT_ARCH=arch_32
    fi
fi

AC_ARG_WITH([ed448-arch],
    [AS_HELP_STRING([--with-ed448-arch=ARCH],
                    [specify the Ed448-Goldilocks architecture])],
    [],
    [with_ed448_arch=${ED448_DEFAULT_ARCH}])

AC_CHECK_LIB(rt, clock_gettime)

dnl Try to detect winsock2 on mingw32/64 systems.
AC_CHECK_LIB(ws2_32, [_head_libws2_32_a])
AC_CHECK_LIB(ws2_32, [_head_lib32_libws2_32_a])
AC_CHECK_LIB(ws2_32, [_head_lib64_libws2_32_a])

AC_SUBST([WARNING_FLAGS],[-Wall])
AC_SUBST([GOLDILOCKS_ARCH],[$with_ed448_arch])

AC_CONFIG_FILES([Makefile
include/Makefile
include/noise/Makefile
include/noise/protocol/Makefile
include/noise/keys/Makefile
src/Makefile
src/protocol/Makefile
src/protobufs/Makefile
src/keys/Makefile
tests/Makefile
tests/unit/Makefile
tests/vector/Makefile
tests/vector-gen/Makefile
tests/performance/Makefile
tools/Makefile
tools/keytool/Makefile
tools/protoc/Makefile
examples/Makefile
examples/echo/Makefile
examples/echo/echo-client/Makefile
examples/echo/echo-keygen/Makefile
examples/echo/echo-server/Makefile
examples/echo/echo-edge/Makefile
doc/Makefile])
AC_OUTPUT
