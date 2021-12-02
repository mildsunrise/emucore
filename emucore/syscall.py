'''Constants / logic related to Linux syscalls.'''

from enum import Enum, unique
from typing import Callable, NamedTuple

__all__ = ['SyscallX64', 'Errno', 'FutexCmd', 'FutexOp']


@unique
class SyscallX64(Enum):
    read = 0
    write = 1
    open = 2
    close = 3
    stat = 4
    fstat = 5
    lstat = 6
    poll = 7
    lseek = 8
    mmap = 9
    mprotect = 10
    munmap = 11
    brk = 12
    rt_sigaction = 13
    rt_sigprocmask = 14
    rt_sigreturn = 15
    ioctl = 16
    pread64 = 17
    pwrite64 = 18
    readv = 19
    writev = 20
    access = 21
    pipe = 22
    select = 23
    sched_yield = 24
    mremap = 25
    msync = 26
    mincore = 27
    madvise = 28
    shmget = 29
    shmat = 30
    shmctl = 31
    dup = 32
    dup2 = 33
    pause = 34
    nanosleep = 35
    getitimer = 36
    alarm = 37
    setitimer = 38
    getpid = 39
    sendfile = 40
    socket = 41
    connect = 42
    accept = 43
    sendto = 44
    recvfrom = 45
    sendmsg = 46
    recvmsg = 47
    shutdown = 48
    bind = 49
    listen = 50
    getsockname = 51
    getpeername = 52
    socketpair = 53
    setsockopt = 54
    getsockopt = 55
    clone = 56
    fork = 57
    vfork = 58
    execve = 59
    exit = 60
    wait4 = 61
    kill = 62
    uname = 63
    semget = 64
    semop = 65
    semctl = 66
    shmdt = 67
    msgget = 68
    msgsnd = 69
    msgrcv = 70
    msgctl = 71
    fcntl = 72
    flock = 73
    fsync = 74
    fdatasync = 75
    truncate = 76
    ftruncate = 77
    getdents = 78
    getcwd = 79
    chdir = 80
    fchdir = 81
    rename = 82
    mkdir = 83
    rmdir = 84
    creat = 85
    link = 86
    unlink = 87
    symlink = 88
    readlink = 89
    chmod = 90
    fchmod = 91
    chown = 92
    fchown = 93
    lchown = 94
    umask = 95
    gettimeofday = 96
    getrlimit = 97
    getrusage = 98
    sysinfo = 99
    times = 100
    ptrace = 101
    getuid = 102
    syslog = 103
    getgid = 104
    setuid = 105
    setgid = 106
    geteuid = 107
    getegid = 108
    setpgid = 109
    getppid = 110
    getpgrp = 111
    setsid = 112
    setreuid = 113
    setregid = 114
    getgroups = 115
    setgroups = 116
    setresuid = 117
    getresuid = 118
    setresgid = 119
    getresgid = 120
    getpgid = 121
    setfsuid = 122
    setfsgid = 123
    getsid = 124
    capget = 125
    capset = 126
    rt_sigpending = 127
    rt_sigtimedwait = 128
    rt_sigqueueinfo = 129
    rt_sigsuspend = 130
    sigaltstack = 131
    utime = 132
    mknod = 133
    uselib = 134
    personality = 135
    ustat = 136
    statfs = 137
    fstatfs = 138
    sysfs = 139
    getpriority = 140
    setpriority = 141
    sched_setparam = 142
    sched_getparam = 143
    sched_setscheduler = 144
    sched_getscheduler = 145
    sched_get_priority_max = 146
    sched_get_priority_min = 147
    sched_rr_get_interval = 148
    mlock = 149
    munlock = 150
    mlockall = 151
    munlockall = 152
    vhangup = 153
    modify_ldt = 154
    pivot_root = 155
    _sysctl = 156
    prctl = 157
    arch_prctl = 158
    adjtimex = 159
    setrlimit = 160
    chroot = 161
    sync = 162
    acct = 163
    settimeofday = 164
    mount = 165
    umount2 = 166
    swapon = 167
    swapoff = 168
    reboot = 169
    sethostname = 170
    setdomainname = 171
    iopl = 172
    ioperm = 173
    create_module = 174
    init_module = 175
    delete_module = 176
    get_kernel_syms = 177
    query_module = 178
    quotactl = 179
    nfsservctl = 180
    getpmsg = 181
    putpmsg = 182
    afs_syscall = 183
    tuxcall = 184
    security = 185
    gettid = 186
    readahead = 187
    setxattr = 188
    lsetxattr = 189
    fsetxattr = 190
    getxattr = 191
    lgetxattr = 192
    fgetxattr = 193
    listxattr = 194
    llistxattr = 195
    flistxattr = 196
    removexattr = 197
    lremovexattr = 198
    fremovexattr = 199
    tkill = 200
    time = 201
    futex = 202
    sched_setaffinity = 203
    sched_getaffinity = 204
    set_thread_area = 205
    io_setup = 206
    io_destroy = 207
    io_getevents = 208
    io_submit = 209
    io_cancel = 210
    get_thread_area = 211
    lookup_dcookie = 212
    epoll_create = 213
    epoll_ctl_old = 214
    epoll_wait_old = 215
    remap_file_pages = 216
    getdents64 = 217
    set_tid_address = 218
    restart_syscall = 219
    semtimedop = 220
    fadvise64 = 221
    timer_create = 222
    timer_settime = 223
    timer_gettime = 224
    timer_getoverrun = 225
    timer_delete = 226
    clock_settime = 227
    clock_gettime = 228
    clock_getres = 229
    clock_nanosleep = 230
    exit_group = 231
    epoll_wait = 232
    epoll_ctl = 233
    tgkill = 234
    utimes = 235
    vserver = 236
    mbind = 237
    set_mempolicy = 238
    get_mempolicy = 239
    mq_open = 240
    mq_unlink = 241
    mq_timedsend = 242
    mq_timedreceive = 243
    mq_notify = 244
    mq_getsetattr = 245
    kexec_load = 246
    waitid = 247
    add_key = 248
    request_key = 249
    keyctl = 250
    ioprio_set = 251
    ioprio_get = 252
    inotify_init = 253
    inotify_add_watch = 254
    inotify_rm_watch = 255
    migrate_pages = 256
    openat = 257
    mkdirat = 258
    mknodat = 259
    fchownat = 260
    futimesat = 261
    newfstatat = 262
    unlinkat = 263
    renameat = 264
    linkat = 265
    symlinkat = 266
    readlinkat = 267
    fchmodat = 268
    faccessat = 269
    pselect6 = 270
    ppoll = 271
    unshare = 272
    set_robust_list = 273
    get_robust_list = 274
    splice = 275
    tee = 276
    sync_file_range = 277
    vmsplice = 278
    move_pages = 279
    utimensat = 280
    epoll_pwait = 281
    signalfd = 282
    timerfd_create = 283
    eventfd = 284
    fallocate = 285
    timerfd_settime = 286
    timerfd_gettime = 287
    accept4 = 288
    signalfd4 = 289
    eventfd2 = 290
    epoll_create1 = 291
    dup3 = 292
    pipe2 = 293
    inotify_init1 = 294
    preadv = 295
    pwritev = 296
    rt_tgsigqueueinfo = 297
    perf_event_open = 298
    recvmmsg = 299
    fanotify_init = 300
    fanotify_mark = 301
    prlimit64 = 302
    name_to_handle_at = 303
    open_by_handle_at = 304
    clock_adjtime = 305
    syncfs = 306
    sendmmsg = 307
    setns = 308
    getcpu = 309
    process_vm_readv = 310
    process_vm_writev = 311
    kcmp = 312
    finit_module = 313
    sched_setattr = 314
    sched_getattr = 315
    renameat2 = 316
    seccomp = 317
    getrandom = 318
    memfd_create = 319
    kexec_file_load = 320
    bpf = 321
    execveat = 322
    userfaultfd = 323
    membarrier = 324
    mlock2 = 325
    copy_file_range = 326
    preadv2 = 327
    pwritev2 = 328
    pkey_mprotect = 329
    pkey_alloc = 330
    pkey_free = 331
    statx = 332
    io_pgetevents = 333
    rseq = 334
    pidfd_send_signal = 424
    io_uring_setup = 425
    io_uring_enter = 426
    io_uring_register = 427
    open_tree = 428
    move_mount = 429
    fsopen = 430
    fsconfig = 431
    fsmount = 432
    fspick = 433
    pidfd_open = 434
    clone3 = 435
    close_range = 436
    openat2 = 437
    pidfd_getfd = 438
    faccessat2 = 439
    process_madvise = 440
    epoll_pwait2 = 441
    mount_setattr = 442
    quotactl_fd = 443
    landlock_create_ruleset = 444
    landlock_add_rule = 445
    landlock_restrict_self = 446
    memfd_secret = 447
    process_mrelease = 448
    futex_waitv = 449

    old_rt_sigaction = 512
    old_rt_sigreturn = 513
    old_ioctl = 514
    old_readv = 515
    old_writev = 516
    old_recvfrom = 517
    old_sendmsg = 518
    old_recvmsg = 519
    old_execve = 520
    old_ptrace = 521
    old_rt_sigpending = 522
    old_rt_sigtimedwait = 523
    old_rt_sigqueueinfo = 524
    old_sigaltstack = 525
    old_timer_create = 526
    old_mq_notify = 527
    old_kexec_load = 528
    old_waitid = 529
    old_set_robust_list = 530
    old_get_robust_list = 531
    old_vmsplice = 532
    old_move_pages = 533
    old_preadv = 534
    old_pwritev = 535
    old_rt_tgsigqueueinfo = 536
    old_recvmmsg = 537
    old_sendmmsg = 538
    old_process_vm_readv = 539
    old_process_vm_writev = 540
    old_setsockopt = 541
    old_getsockopt = 542
    old_io_setup = 543
    old_io_submit = 544
    old_execveat = 545
    old_preadv2 = 546
    old_pwritev2 = 547


# from include/uapi/asm-generic/errno-base.h @ 6f52b16
# from include/uapi/asm-generic/errno.h @ 6f52b16

class Errno(Enum):
    # BASE ERRNO VALUES

    EPERM            = 1	# Operation not permitted
    ENOENT           = 2	# No such file or directory
    ESRCH            = 3	# No such process
    EINTR            = 4	# Interrupted system call
    EIO              = 5	# I/O error
    ENXIO            = 6	# No such device or address
    E2BIG            = 7	# Argument list too long
    ENOEXEC          = 8	# Exec format error
    EBADF            = 9	# Bad file number
    ECHILD           = 10	# No child processes
    EAGAIN           = 11	# Try again
    ENOMEM           = 12	# Out of memory
    EACCES           = 13	# Permission denied
    EFAULT           = 14	# Bad address
    ENOTBLK          = 15	# Block device required
    EBUSY            = 16	# Device or resource busy
    EEXIST           = 17	# File exists
    EXDEV            = 18	# Cross-device link
    ENODEV           = 19	# No such device
    ENOTDIR          = 20	# Not a directory
    EISDIR           = 21	# Is a directory
    EINVAL           = 22	# Invalid argument
    ENFILE           = 23	# File table overflow
    EMFILE           = 24	# Too many open files
    ENOTTY           = 25	# Not a typewriter
    ETXTBSY          = 26	# Text file busy
    EFBIG            = 27	# File too large
    ENOSPC           = 28	# No space left on device
    ESPIPE           = 29	# Illegal seek
    EROFS            = 30	# Read-only file system
    EMLINK           = 31	# Too many links
    EPIPE            = 32	# Broken pipe
    EDOM             = 33	# Math argument out of domain of func
    ERANGE           = 34	# Math result not representable

    # OTHER ERRNO VALUES

    EDEADLK          = 35	# Resource deadlock would occur
    ENAMETOOLONG     = 36	# File name too long
    ENOLCK           = 37	# No record locks available

    # This error code is special: arch syscall entry code will return
    # -ENOSYS if users try to call a syscall that doesn't exist.  To keep
    # failures of syscalls that really do exist distinguishable from
    # failures due to attempts to use a nonexistent syscall, syscall
    # implementations should refrain from returning -ENOSYS.
    ENOSYS           = 38	# Invalid system call number

    ENOTEMPTY        = 39	# Directory not empty
    ELOOP            = 40	# Too many symbolic links encountered
    EWOULDBLOCK      = EAGAIN	# Operation would block
    ENOMSG           = 42	# No message of desired type
    EIDRM            = 43	# Identifier removed
    ECHRNG           = 44	# Channel number out of range
    EL2NSYNC         = 45	# Level 2 not synchronized
    EL3HLT           = 46	# Level 3 halted
    EL3RST           = 47	# Level 3 reset
    ELNRNG           = 48	# Link number out of range
    EUNATCH          = 49	# Protocol driver not attached
    ENOCSI           = 50	# No CSI structure available
    EL2HLT           = 51	# Level 2 halted
    EBADE            = 52	# Invalid exchange
    EBADR            = 53	# Invalid request descriptor
    EXFULL           = 54	# Exchange full
    ENOANO           = 55	# No anode
    EBADRQC          = 56	# Invalid request code
    EBADSLT          = 57	# Invalid slot

    EDEADLOCK        = EDEADLK

    EBFONT           = 59	# Bad font file format
    ENOSTR           = 60	# Device not a stream
    ENODATA          = 61	# No data available
    ETIME            = 62	# Timer expired
    ENOSR            = 63	# Out of streams resources
    ENONET           = 64	# Machine is not on the network
    ENOPKG           = 65	# Package not installed
    EREMOTE          = 66	# Object is remote
    ENOLINK          = 67	# Link has been severed
    EADV             = 68	# Advertise error
    ESRMNT           = 69	# Srmount error
    ECOMM            = 70	# Communication error on send
    EPROTO           = 71	# Protocol error
    EMULTIHOP        = 72	# Multihop attempted
    EDOTDOT          = 73	# RFS specific error
    EBADMSG          = 74	# Not a data message
    EOVERFLOW        = 75	# Value too large for defined data type
    ENOTUNIQ         = 76	# Name not unique on network
    EBADFD           = 77	# File descriptor in bad state
    EREMCHG          = 78	# Remote address changed
    ELIBACC          = 79	# Can not access a needed shared library
    ELIBBAD          = 80	# Accessing a corrupted shared library
    ELIBSCN          = 81	# .lib section in a.out corrupted
    ELIBMAX          = 82	# Attempting to link in too many shared libraries
    ELIBEXEC         = 83	# Cannot exec a shared library directly
    EILSEQ           = 84	# Illegal byte sequence
    ERESTART         = 85	# Interrupted system call should be restarted
    ESTRPIPE         = 86	# Streams pipe error
    EUSERS           = 87	# Too many users
    ENOTSOCK         = 88	# Socket operation on non-socket
    EDESTADDRREQ     = 89	# Destination address required
    EMSGSIZE         = 90	# Message too long
    EPROTOTYPE       = 91	# Protocol wrong type for socket
    ENOPROTOOPT      = 92	# Protocol not available
    EPROTONOSUPPORT  = 93	# Protocol not supported
    ESOCKTNOSUPPORT  = 94	# Socket type not supported
    EOPNOTSUPP       = 95	# Operation not supported on transport endpoint
    EPFNOSUPPORT     = 96	# Protocol family not supported
    EAFNOSUPPORT     = 97	# Address family not supported by protocol
    EADDRINUSE       = 98	# Address already in use
    EADDRNOTAVAIL    = 99	# Cannot assign requested address
    ENETDOWN         = 100	# Network is down
    ENETUNREACH      = 101	# Network is unreachable
    ENETRESET        = 102	# Network dropped connection because of reset
    ECONNABORTED     = 103	# Software caused connection abort
    ECONNRESET       = 104	# Connection reset by peer
    ENOBUFS          = 105	# No buffer space available
    EISCONN          = 106	# Transport endpoint is already connected
    ENOTCONN         = 107	# Transport endpoint is not connected
    ESHUTDOWN        = 108	# Cannot send after transport endpoint shutdown
    ETOOMANYREFS     = 109	# Too many references: cannot splice
    ETIMEDOUT        = 110	# Connection timed out
    ECONNREFUSED     = 111	# Connection refused
    EHOSTDOWN        = 112	# Host is down
    EHOSTUNREACH     = 113	# No route to host
    EALREADY         = 114	# Operation already in progress
    EINPROGRESS      = 115	# Operation now in progress
    ESTALE           = 116	# Stale file handle
    EUCLEAN          = 117	# Structure needs cleaning
    ENOTNAM          = 118	# Not a XENIX named type file
    ENAVAIL          = 119	# No XENIX semaphores available
    EISNAM           = 120	# Is a named type file
    EREMOTEIO        = 121	# Remote I/O error
    EDQUOT           = 122	# Quota exceeded

    ENOMEDIUM        = 123	# No medium found
    EMEDIUMTYPE      = 124	# Wrong medium type
    ECANCELED        = 125	# Operation Canceled
    ENOKEY           = 126	# Required key not available
    EKEYEXPIRED      = 127	# Key has expired
    EKEYREVOKED      = 128	# Key has been revoked
    EKEYREJECTED     = 129	# Key was rejected by service

    # for robust mutexes
    EOWNERDEAD       = 130	# Owner died
    ENOTRECOVERABLE  = 131	# State not recoverable

    ERFKILL          = 132	# Operation not possible due to RF-kill

    EHWPOISON        = 133	# Memory page has hardware error


# from include/uapi/linux/futex.h @ bf69bad

class FutexCmd(NamedTuple):
    @unique
    class Nr(Enum):
        WAIT             = 0
        WAKE             = 1
        FD               = 2
        REQUEUE          = 3
        CMP_REQUEUE      = 4
        WAKE_OP          = 5
        LOCK_PI          = 6
        UNLOCK_PI        = 7
        TRYLOCK_PI       = 8
        WAIT_BITSET      = 9
        WAKE_BITSET      = 10
        WAIT_REQUEUE_PI  = 11
        CMP_REQUEUE_PI   = 12
        LOCK_PI2         = 13

    nr: Nr
    private: bool
    clock_realtime: bool

    @staticmethod
    def load(cmd: int):
        assert isinstance(cmd, int)
        parse_flag = lambda cmd, flag: (cmd & ~flag, bool(cmd & flag))
        cmd, private        = parse_flag(cmd, 1 << 7)
        cmd, clock_realtime = parse_flag(cmd, 1 << 8)
        nr = FutexCmd.Nr(cmd)
        return FutexCmd(nr=nr, private=private, clock_realtime=clock_realtime)

    def save(self) -> int:
        cmd = self.nr.value
        if self.private: cmd |= 1 << 7
        if self.clock_realtime: cmd |= 1 << 8
        return cmd

class FutexOp(NamedTuple):
    @unique
    class Op(Enum):
        SET   = 0, (lambda p, arg:      arg)
        ADD   = 1, (lambda p, arg: p +  arg)
        OR    = 2, (lambda p, arg: p |  arg)
        ANDN  = 3, (lambda p, arg: p & ~arg)
        XOR   = 4, (lambda p, arg: p ^  arg)

        def __new__(cls, value, *kargs):
            obj = object.__new__(cls)
            obj._value_ = value
            return obj

        impl: Callable[[int, int], int]

        def __init__(self, _, impl):
            self.impl = impl

    @unique
    class Cmp(Enum):
        CMP_EQ = 0, (lambda p, arg: p == arg)
        CMP_NE = 1, (lambda p, arg: p != arg)
        CMP_LT = 2, (lambda p, arg: p <  arg)
        CMP_LE = 3, (lambda p, arg: p <= arg)
        CMP_GT = 4, (lambda p, arg: p >  arg)
        CMP_GE = 5, (lambda p, arg: p >= arg)

        def __new__(cls, value, *kargs):
            obj = object.__new__(cls)
            obj._value_ = value
            return obj

        impl: Callable[[int, int], bool]

        def __init__(self, _, impl):
            self.impl = impl

    op: Op
    oparg_shift: bool   # Use (1 << OPARG) instead of OPARG.
    oparg: int
    cmp: Cmp
    cmparg: int

    @property
    def effective_oparg(self) -> int:
        # FIXME: sign extension?
        return (1 << self.oparg_shift) if self.oparg_shift else self.oparg
    def new_value(self, old: int) -> int:
        return self.op.impl(old, self.effective_oparg)
    def compare(self, old: int) -> int:
        return self.cmp.impl(old, self.cmparg)

    @staticmethod
    def load(cmd: int):
        assert isinstance(cmd, int)
        if cmd >> 32: raise ValueError()
        return FutexOp(oparg_shift=bool(cmd >> 31),
            op=FutexOp.Op((cmd >> 28) & 7), cmp=FutexOp.Cmp((cmd >> 24) & 0xF),
            oparg=((cmd >> 12) & 0xFFF),    cmparg=((cmd) & 0xFFF))

    def save(self) -> int:
        assert not (self.oparg >> 12) and not (self.cmparg >> 12)
        return (int(self.oparg_shift) << 31) \
            | (self.op.value << 28) | (self.cmp.value << 24) \
            | (self.oparg << 12)    | (self.cmparg)
