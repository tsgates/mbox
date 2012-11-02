from ptrace.cpu_info import CPU_WORD_SIZE
from ptrace.ctypes_tools import ntoh_ushort, ntoh_uint
from ptrace.syscall import SYSCALL_PROTOTYPES
from ptrace.syscall.socketcall_constants import SOCKETCALL, SOCKET_FAMILY
from ptrace.syscall.socketcall_struct import sockaddr, sockaddr_in, sockaddr_in6, sockaddr_un
from ctypes import c_int
from ptrace.os_tools import RUNNING_LINUX
from socket import AF_INET, AF_INET6, inet_ntoa
from struct import pack
if RUNNING_LINUX:
    from socket import AF_NETLINK
    from ptrace.syscall.socketcall_struct import sockaddr_nl

AF_FILE = 1

def formatOptVal(argument):
    function = argument.function
    optlen = function["optlen"].value
    if optlen == 4:
        addr = argument.value
        text = function.process.readStruct(addr, c_int)
        return argument.formatPointer("<%s>" % text, addr)
    else:
        return None

def formatSockaddr(argument, argtype):
    address = argument.value
    value = argument.function.process.readStruct(address, sockaddr)
    family = value.family
    if family == AF_INET:
        return argument.readStruct(address, sockaddr_in)
    if family == AF_INET6:
        return argument.readStruct(address, sockaddr_in6)
    if family == AF_FILE:
        return argument.readStruct(address, sockaddr_un)
    if RUNNING_LINUX:
        if family == AF_NETLINK:
            return argument.readStruct(address, sockaddr_nl)
    family = SOCKET_FAMILY.get(family, family)
    return argument.formatPointer("<sockaddr family=%s>" % family, address)

def setupSocketCall(function, process, socketcall, address):
    # Reset function call
    function.clearArguments()
#    function.argument_class = SocketCallArgument

    # Setup new function call
    function.process = process
    function.name = socketcall.getText()

    # Create arguments
    function.restype, formats = SYSCALL_PROTOTYPES[function.name]
    for argtype, argname in formats:
        value = process.readWord(address)
        function.addArgument(value, argname, argtype)
        address += CPU_WORD_SIZE

def formatSockaddrInStruct(argument, name, value):
    if name == "sin_port":
        return ntoh_ushort(value)
    return None

def formatSockaddrIn6Struct(argument, name, value):
    if name == "sin6_port":
        return ntoh_ushort(value)
    #if name == "sin6_addr":
        # FIXME: ...
    return None

