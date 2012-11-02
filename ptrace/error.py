from sys import exc_info
from traceback import format_exception
from logging import ERROR, getLogger
from ptrace.logging_tools import getLogFunc, changeLogLevel

PTRACE_ERRORS = Exception

def writeBacktrace(logger, log_level=ERROR):
    """
    Write a backtrace into the logger with the specified log level.
    """
    log_func = getLogFunc(logger, log_level)
    try:
        info = exc_info()
        trace = format_exception(*info)
        if trace[0] != "None\n":
            trace = ''.join(trace).rstrip()
            for line in trace.split("\n"):
                log_func(line.rstrip())
            return
    except:
        pass
    log_func("Unable to get backtrace")

def formatError(error):
    """
    Format an error as a string. Write the error type as prefix.
    Eg. "[ValueError] invalid value".
    """
    return "[%s] %s" % (error.__class__.__name__, error)

def writeError(logger, error, title="ERROR", log_level=ERROR):
    """
    Write an error into the logger:
     - logger: the logger (if None, use getLogger())
     - error: the exception objet
     - title: error message prefix (eg. title="Initialization error")
     - log_level: log level of the error

    If the exception is a SystemExit or a KeyboardInterrupt, re-emit
    (raise) the exception and don't write it.
    """
    if not logger:
        logger = getLogger()
    if error.__class__ in (SystemExit, KeyboardInterrupt):
        raise error
    log_func = getLogFunc(logger, log_level)
    log_func("%s: %s" % (title, formatError(error)))
    writeBacktrace(logger, log_level=changeLogLevel(log_level, -1))

class PtraceError(Exception):
    """
    Ptrace error: have the optional attributes errno and pid.
    """
    def __init__(self, message, errno=None, pid=None):
        Exception.__init__(self, message)
        self.errno = errno
        self.pid = pid

