"""
Function get_errno(): get the current errno value.

Try different implementations:
 - ctypes_support.get_errno() function
 - __errno_location_sym symbol from the C library
 - PyErr_SetFromErrno() from the C Python API
"""

get_errno = None
try:
    from ctypes_support import get_errno
except ImportError:
    pass

if not get_errno:
    from ctypes import POINTER, c_int

    def _errno_location():
        """
        Try to get errno integer from libc using __errno_location_sym function.

        This function is specific to OS with "libc.so.6" and may fails for
        thread-safe libc.
        """
        from ctypes import cdll
        try:
            libc = cdll.LoadLibrary("libc.so.6")
        except OSError:
            # Unable to open libc dynamic library
            return None
        try:
            __errno_location = libc.__errno_location_sym
        except AttributeError:
            # libc doesn't have __errno_location
            return None
        __errno_location.restype = POINTER(c_int)
        return __errno_location()[0]

    errno = _errno_location()
    if errno is not None:
        def get_errno():
            # pyflakes warn about "undefined name",
            # but that's wrong: errno is defined!
            return errno
    else:
        del errno

if not get_errno:
    from ctypes import pythonapi, py_object

    # Function from pypy project:
    # File pypy/dist/pypy/rpython/rctypes/aerrno.py
    def _pythonapi_geterrno():
        """
        Read errno using Python C API: raise an exception with PyErr_SetFromErrno
        and then read error code 'errno'.

        This function may raise an RuntimeError.
        """
        try:
            pythonapi.PyErr_SetFromErrno(py_object(OSError))
        except OSError, err:
            return err.errno
        else:
            raise RuntimeError("get_errno() is unable to get error code")

    get_errno = _pythonapi_geterrno

__all__ = ["get_errno"]

