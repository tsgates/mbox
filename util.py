#!/usr/bin/env python2

import os
import stat
import shutil

from os.path import exists
from os.path import join
from os.path import normpath

def safecopy(src, dst):
    assert file_exists(src) and not file_exists(dst)
    shutil.copyfile(src, dst)
    
def safestat(pn):
    try:
        return os.stat(pn)
    except OSError:
        return None

def dir_exists(pn):
    s = safestat(pn)
    return s and stat.S_ISDIR(s.st_mode)

def file_exists(pn):
    s = safestat(pn)
    return s and stat.S_ISREG(s.st_mode)

def mkdir(pn):
    return os.mkdir(pn)

def chjoin(root, *paths):
    pn = [p.lstrip("/") for p in paths]
    np = normpath(join(root, *pn))
    
    # escaped by multiple ..
    if not np.startswith(root):
        return root
    return np

def itercrumb(path, strip=False):
    assert path.startswith("/")
    pn = path.rstrip("/")
    pn = normpath(pn)
    
    head = "/"
    for crumb in pn[1:].split("/"):
        head += crumb + "/"
        if strip:
            yield head[1:]
        else:
            yield head
