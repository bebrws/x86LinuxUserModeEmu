//
//  errno.c
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//
#include <errno.h>

#include "debug.h"
#include "errno.h"

int err_map(int err) {
#define ERRCASE(err) \
        case err: return _##err;
    switch (err) {
        ERRCASE(EPERM)
        ERRCASE(ENOENT)
        ERRCASE(ESRCH)
        ERRCASE(EINTR)
        ERRCASE(EIO)
        ERRCASE(ENXIO)
        ERRCASE(E2BIG)
        ERRCASE(ENOEXEC)
        ERRCASE(EBADF)
        ERRCASE(ECHILD)
        ERRCASE(EAGAIN)
        ERRCASE(ENOMEM)
        ERRCASE(EACCES)
        ERRCASE(EFAULT)
        ERRCASE(ENOTBLK)
        ERRCASE(EBUSY)
        ERRCASE(EEXIST)
        ERRCASE(EXDEV)
        ERRCASE(ENODEV)
        ERRCASE(ENOTDIR)
        ERRCASE(EISDIR)
        ERRCASE(EINVAL)
        ERRCASE(ENFILE)
        ERRCASE(EMFILE)
        ERRCASE(ENOTTY)
        ERRCASE(ETXTBSY)
        ERRCASE(EFBIG)
        ERRCASE(ENOSPC)
        ERRCASE(ESPIPE)
        ERRCASE(EROFS)
        ERRCASE(EMLINK)
        ERRCASE(EPIPE)
        ERRCASE(EDOM)
        ERRCASE(ERANGE)
        ERRCASE(EDEADLK)
        ERRCASE(ENAMETOOLONG)
        ERRCASE(ENOLCK)
        ERRCASE(ENOSYS)
        ERRCASE(ENOTEMPTY)
        ERRCASE(ELOOP)
        ERRCASE(ENOSTR)
        ERRCASE(ENODATA)
        ERRCASE(ETIME)
        ERRCASE(ENOSR)
        ERRCASE(EREMOTE)
        ERRCASE(ENOLINK)
        ERRCASE(EPROTO)
        ERRCASE(EMULTIHOP)
        ERRCASE(EBADMSG)
        ERRCASE(EOVERFLOW)
        ERRCASE(EILSEQ)
        ERRCASE(EUSERS)
        ERRCASE(ENOTSOCK)
        ERRCASE(EDESTADDRREQ)
        ERRCASE(EMSGSIZE)
        ERRCASE(EPROTOTYPE)
        ERRCASE(ENOPROTOOPT)
        ERRCASE(EPROTONOSUPPORT)
        ERRCASE(ESOCKTNOSUPPORT)
        ERRCASE(EOPNOTSUPP)
        ERRCASE(EPFNOSUPPORT)
        ERRCASE(EAFNOSUPPORT)
        ERRCASE(EADDRINUSE)
        ERRCASE(EADDRNOTAVAIL)
        ERRCASE(ENETDOWN)
        ERRCASE(ENETUNREACH)
        ERRCASE(ENETRESET)
        ERRCASE(ECONNABORTED)
        ERRCASE(ECONNRESET)
        ERRCASE(ENOBUFS)
        ERRCASE(EISCONN)
        ERRCASE(ENOTCONN)
        ERRCASE(ESHUTDOWN)
        ERRCASE(ETOOMANYREFS)
        ERRCASE(ETIMEDOUT)
        ERRCASE(ECONNREFUSED)
        ERRCASE(EHOSTDOWN)
        ERRCASE(EHOSTUNREACH)
        ERRCASE(EALREADY)
        ERRCASE(EINPROGRESS)
        ERRCASE(ESTALE)
        ERRCASE(EDQUOT)
    }
#undef ERRCASE
    debugger;
    return -1337; // TODO FIXME XXX
}

int errno_map() {
//    if (errno == EPIPE)
//        send_signal(current, SIGPIPE_, SIGINFO_NIL);
    return err_map(errno);
}
