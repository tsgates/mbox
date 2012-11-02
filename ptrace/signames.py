"""
Name of process signals.

SIGNAMES contains a dictionary mapping a signal number to it's name. But you
should better use signalName() instead of SIGNAMES since it returns a string
even if the signal is unknown.
"""

PREFERRED_NAMES = ("SIGABRT", "SIGHUP", "SIGCHLD", "SIGPOLL")

def getSignalNames():
    """
    Create signal names dictionay (eg. 9 => 'SIGKILL') using dir(signal).
    If multiple signal names have the same number, use the first matching name
    in PREFERRED_NAME to select preferred name (eg. SIGIOT=SIGABRT=17).
    """
    import signal
    allnames = {}
    for name in dir(signal):
        if not name.startswith("SIG"):
            continue
        signum = getattr(signal,name)
        try:
            allnames[signum].append(name)
        except KeyError:
            allnames[signum] = [name]
    signames = {}
    for signum, names in allnames.iteritems():
        if not signum:
            # Skip signal 0
            continue
        name = None
        for preferred in PREFERRED_NAMES:
            if preferred in names:
                name = preferred
                break
        if not name:
            name = names[0]
        signames[signum] = name
    return signames
SIGNAMES = getSignalNames()

def signalName(signum):
    """
    Get the name of a signal

    >>> from signal import SIGINT
    >>> signalName(SIGINT)
    'SIGINT'
    >>> signalName(404)
    'signal<404>'
    """
    try:
        return SIGNAMES[signum]
    except KeyError:
        return "signal<%s>" % signum

