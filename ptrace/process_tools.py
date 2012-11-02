from ptrace.os_tools import RUNNING_LINUX, RUNNING_WINDOWS
if RUNNING_LINUX:
    from ptrace.linux_proc import (ProcError, openProc,
        readProcessProcList, readProcessLink, readProcessStat)
from ptrace.signames import signalName
if not RUNNING_WINDOWS:
    from os import (
        WIFSTOPPED, WSTOPSIG,
        WIFSIGNALED, WTERMSIG,
        WIFEXITED, WEXITSTATUS,
        WCOREDUMP)

def dumpProcessInfo(log, pid, max_length=None):
    """
    Dump all information about a process:
     - log: callback to write display one line
     - pid: process identifier
     - max_length (default: None): maximum number of environment variables
    """
    if not RUNNING_LINUX:
        log("Process ID: %s" % pid)
        return
    try:
        stat = readProcessStat(pid)
    except ProcError:
        # Permission denied
        stat = None
    text = "Process ID: %s" % pid
    if stat:
        text += " (parent: %s)" % stat.ppid
    log(text)
    if stat:
        state = stat.state
        try:
            state = "%s (%s)" % (state, stat.STATE_NAMES[state])
        except KeyError:
            pass
        log("Process state: %s" % state)
    try:
        log("Process command line: %r" % readProcessProcList(pid, 'cmdline'))
    except ProcError:
        # Permission denied
        pass
    try:
        env = readProcessProcList(pid, 'environ')
        if max_length:
            # Truncate environment if it's too long
            length = 0
            removed = 0
            index = 0
            while index < len(env):
                var = env[index]
                if max_length < length+len(var):
                    del env[index]
                    removed += 1
                else:
                    length += len(var)
                    index += 1
            env = ', '.join( "%s=%r" % tuple(item.split("=", 1)) for item in env )
            if removed:
                env += ', ... (skip %s vars)' % removed
        log("Process environment: %s" % env)
    except ProcError:
        # Permission denied
        pass
    try:
        log("Process working directory: %s" % readProcessLink(pid, 'cwd'))
    except ProcError:
        # Permission denied
        pass

    try:
        user = None
        group = None
        status_file = openProc("%s/status" % pid)
        for line in status_file:
            if line.startswith("Uid:"):
                user = [ int(id) for id in line[5:].split("\t") ]
            if line.startswith("Gid:"):
                group = [ int(id) for id in line[5:].split("\t") ]
        status_file.close()
        if user:
            text = "User identifier: %s" % user[0]
            if user[0] != user[1]:
                text += " (effective: %s)" % user[1]
            log(text)
        if group:
            text = "Group identifier: %s" % group[0]
            if group[0] != group[1]:
                text += " (effective: %s)" % group[1]
            log(text)
    except ProcError:
        # Permission denied
        pass

def formatProcessStatus(status, title="Process"):
    """
    Format a process status (integer) as a string.
    """
    if RUNNING_WINDOWS:
        raise NotImplementedError()
    if WIFSTOPPED(status):
        signum = WSTOPSIG(status)
        text = "%s stopped by signal %s" % (title, signalName(signum))
    elif WIFSIGNALED(status):
        signum = WTERMSIG(status)
        text = "%s killed by signal %s" % (title, signalName(signum))
    else:
        if not WIFEXITED(status):
            raise ValueError("Invalid status: %r" % status)

        exitcode = WEXITSTATUS(status)
        if exitcode:
            text = "%s exited with code %s" % (title, exitcode)
        else:
            text = "%s exited normally" % title
    if WCOREDUMP(status):
        text += " (core dumped)"
    return text

