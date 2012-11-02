from ptrace.error import PtraceError

class ProcessError(PtraceError):
    def __init__(self, process, message):
        PtraceError.__init__(self, message, pid=process.pid)
        self.process = process

