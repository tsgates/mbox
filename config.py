#!/usr/bin/env python2

import os
import re
import sys

def reget(regexp, haystack):
    m = re.match(regexp, haystack)
    if not m:
        raise "'%s' =/~ '%s'" % (haystack, regexp)
    grp = m.groups()
    if len(grp) != 1:
        raise "pared %s" % ",".join(grp)
    return grp[0]

class Conf:
    def __init__(self, defs={}):
        self.conf = {}
        self.defs = defs
    def load(self, path):
        with open(path) as fd:
            self.loads(fd.read())
    def loads(self, string):
        sec = None
        for l in string.splitlines():
            l = l.strip()
            if l == "" or re.match("^[ \t]*#.*", l):
                continue
            if l.startswith("["):
                sec = reget("\[([^]]+)\]", l)
                self.conf[sec] = {}
                continue
            (k, v) = l.split(":")
            k = k.strip()
            v = v.strip()
            for (varname, vardef) in self.defs.iteritems():
                if varname in v:
                    v = v.replace(varname, vardef)
            if not k in self.conf[sec]:
                self.conf[sec][k] = []
            self.conf[sec][k].append(v)

    def get(self, sec, key = None, default = None):
        if not sec in self.conf:
            return default
        if key == None:
            return self.conf[sec]
        if key in self.conf[sec]:
            return self.conf[sec][key]
        return default

    def get_one(self, sec, key = None, default = None):
        ele = self.get(sec, key, default)
        if ele is not None and len(ele) == 1:
            return ele[0]
        return ele

if __name__ == '__main__':
    import pprint
    c = Conf({"~": os.path.expanduser("~")})
    c.load(sys.argv[1])
    pprint.pprint(c.conf)