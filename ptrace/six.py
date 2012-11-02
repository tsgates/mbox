# Copy/paste useful parts of six, a module written by Benjamin Peterson and
# distributed under the MIT license:
# http://pypi.python.org/pypi/six/

import sys

PY3 = sys.version_info[0] == 3

if PY3:
    binary_type = bytes

    def b(s):
        return s.encode("latin-1")
else:
    binary_type = str

    def b(s):
        return s
