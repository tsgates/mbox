"""
Functions and variables to access to Linux proc directory.

Constant:

   - PAGE_SIZE: size of a memory page
"""
from __future__ import with_statement
from os import readlink, listdir
from resource import getpagesize
from ptrace.tools import timestampUNIX
from datetime import timedelta

PAGE_SIZE = getpagesize()

class ProcError(Exception):
    """
    Linux proc directory error.
    """
    pass

def openProc(path):
    """
    Open a proc entry in read only mode.
    """
    filename = "/proc/%s" % path
    try:
        return open(filename)
    except IOError, err:
        raise ProcError("Unable to open %r: %s" % (filename, err))

def readProc(path):
    """
    Read the content of a proc entry.
    Eg. readProc("stat") to read /proc/stat.
    """
    with openProc(path) as procfile:
        return procfile.read()

def readProcessProc(pid, key):
    """
    Read the content of a process entry in the proc directory.
    Eg. readProcessProc(pid, "status") to read /proc/pid/status.
    """
    try:
        filename = "/proc/%s/%s" % (pid, key)
        with open(filename) as proc:
            return proc.read()
    except IOError, err:
        raise ProcError("Process %s doesn't exist: %s" % (pid, err))

class ProcessState(object):
    """
    Processus state. Attributes:
    - state (str): process status ('R', 'S', 'T', ...)
    - program (str): program name
    - pid (int): process identifier
    - ppid (int): parent process identifier
    - pgrp (int): process group
    - session (int): session identifier
    - tty_nr (int): tty number
    - tpgid (int)
    - utime (int): user space time (jiffies)
    - stime (int): kernel space time (jiffies)
    - starttime (int): start time
    """
    STATE_NAMES = {
        "R": "running",
        "S": "sleeping",
        "D": "disk",
        "Z": "zombie",
        "T": "traced",
        "W": "pagging",
    }
    def __init__(self, stat):
        # pid (program) ... => "pid (program", "..."
        part, stat = stat.rsplit(')', 1)
        self.pid, self.program = part.split('(', 1)
        self.pid = int(self.pid)

        # "state ..." => state, "..."
        stat = stat.split()
        self.state = stat[0]
        stat = [ int(item) for item in stat[1:] ]

        # Read next numbers
        self.ppid = stat[0]
        self.pgrp = stat[1]
        self.session = stat[2]
        self.tty_nr = stat[3]
        self.tpgid = stat[4]
        self.utime = stat[10]
        self.stime = stat[11]
        self.starttime = stat[18]

def readProcessStat(pid):
    """
    Read the process state ('stat') as a ProcessState object.
    """
    stat = readProcessProc(pid, 'stat')
    return ProcessState(stat)

def readProcessStatm(pid):
    """
    Read the process memory status ('statm') as a list of integers.
    Values are in bytes (and not in pages).
    """
    statm = readProcessProc(pid, 'statm')
    statm = [ int(item)*PAGE_SIZE for item in statm.split() ]
    return statm

def readProcessProcList(pid, key):
    """
    Read a process entry as a list of strings.
    """
    data = readProcessProc(pid, key)
    if not data:
        # Empty file: empty list
        return []
    data = data.split("\0")
    if not data[-1]:
        del data[-1]
    return data

def readProcessLink(pid, key):
    """
    Read a process link.
    """
    try:
        filename = "/proc/%s/%s" % (pid, key)
        return readlink(filename)
    except OSError, err:
        raise ProcError("Unable to read proc link %r: %s" % (filename, err))

def readProcesses():
    """
    Read all processes identifiers. The function is a generator,
    use it with: ::

       for pid in readProcesses(): ...
    """
    for filename in listdir('/proc'):
        try:
            yield int(filename)
        except ValueError:
            # Filename is not an integer (eg. "stat" from /proc/stat)
            continue

def readProcessCmdline(pid, escape_stat=True):
    """
    Read the process command line. If escape_stat is True, format program name
    with "[%s]" if the process has no command line, eg. "[khelper]".
    """
    # Try /proc/42/cmdline
    try:
        cmdline = readProcessProcList(pid, 'cmdline')
        if cmdline:
            return cmdline
    except ProcError:
        pass

    # Try /proc/42/stat
    try:
        stat = readProcessStat(pid)
        program = stat.program
        if escape_stat:
            program = "[%s]" % program
        return [program]
    except ProcError:
        return None

def searchProcessesByName(process_name):
    """
    Find all processes matching the program name pattern.
    Eg. pattern "ssh" will find the program "/usr/bin/ssh".

    This function is a generator yielding the process identifier,
    use it with: ::

       for pid in searchProcessByName(pattern):
          ...
    """
    suffix = '/'+process_name
    for pid in readProcesses():
        cmdline = readProcessCmdline(pid)
        if not cmdline:
            continue
        program = cmdline[0]
        if program == process_name or program.endswith(suffix):
            yield pid

def searchProcessByName(process_name):
    """
    Function similar to searchProcessesByName() but only return the identifier
    of the first matching process. Raise a ProcError if there is no matching
    process.
    """
    for pid in searchProcessesByName(process_name):
        return pid
    raise ProcError("Unable to find process: %r" % process_name)

def getUptime():
    """
    Get the system uptime as a datetime.timedelta object.
    """
    uptime = readProc('uptime')
    uptime = uptime.strip().split()
    uptime = float(uptime[0])
    return timedelta(seconds=uptime)

def getSystemBoot():
    """
    Get the system boot date as a datetime.datetime object.
    """
    if getSystemBoot.value is None:
        stat_file = openProc('stat')
        for line in stat_file:
            if not line.startswith("btime "):
                continue
            seconds = int(line[6:])
            btime = timestampUNIX(seconds, True)
            getSystemBoot.value = btime
            break
        stat_file.close()
        if getSystemBoot.value is None:
            raise ProcError("Unable to read system boot time!")
    return getSystemBoot.value
getSystemBoot.value = None

