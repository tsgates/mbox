from ptrace.syscall.socketcall_constants import (
    SOCKET_FAMILY, SOCKET_TYPE, SOCKET_PROTOCOL,
    SETSOCKOPT_LEVEL, SETSOCKOPT_OPTNAME)

SYSCALL_ARG_DICT = {
    "lseek": {
        "origin": {0: "SEEK_SET", 1: "SEEK_CUR", 2: "SEEK_END"},
    },
    "futex": {
        "op": {
            0: "FUTEX_WAIT",
            1: "FUTEX_WAKE",
            2: "FUTEX_FD",
            3: "FUTEX_REQUEUE",
            4: "FUTEX_CMP_REQUEUE",
            5: "FUTEX_WAKE_OP",
            6: "FUTEX_LOCK_PI",
            7: "FUTEX_UNLOCK_PI",
            8: "FUTEX_TRYLOCK_PI",
        },
    },
    "fcntl": {
        "cmd": {
            0: "F_DUPFD",
            1: "F_GETFD",
            2: "F_SETFD",
            3: "F_GETFL",
            4: "F_SETFL",
            5: "F_GETOWN",
            6: "F_SETOWN",
            7: "F_GETLK",
            8: "F_SETLK",
            9: "F_SETLKW",
        },
    },
    "ipc": {
        "call": {
            1: "SEMOP",
            2: "SEMGET",
            3: "SEMCTL",
            4: "SEMTIMEDOP",
            11: "MSGSND",
            12: "MSGRCV",
            13: "MSGGET",
            14: "MSGCTL",
            21: "SHMAT",
            22: "SHMDT",
            23: "SHMGET",
            24: "SHMCTL",
        },
    },
    "socket": {
        "family": SOCKET_FAMILY,
        "type": SOCKET_TYPE,
        "protocol": SOCKET_PROTOCOL,
    },
    "getsockopt": {
        "level": SETSOCKOPT_LEVEL,
        "optname": SETSOCKOPT_OPTNAME,
    },
}

SYSCALL_ARG_DICT["setsockopt"] = SYSCALL_ARG_DICT["getsockopt"]

