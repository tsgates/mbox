import os
import re
import util

class ask_diff:
    desc = "d:diff"
    def __call__(self, spn, hpn):
        os.system("diff -urN '%s' '%s'" % (hpn, spn))

class ask_view:
    desc = "v:view"
    def __call__(self, spn, hpn):
        os.system("cat '%s'" % (spn))

class ask_ignore:
    desc = "i:ignore"
    def __call__(self, spn, hpn):
        return True

class ask_commit:
    desc = "c:commit"
    def __call__(self, spn, hpn):
        return True

class ask_quit:
    desc = "q:quit"
    def __call__(self, spn, hpn):
        exit(0)

class ask_commitall:
    desc = "C:commit(all)"
    def __call__(self, spn, hpn):
        # XXX. ignore signals
        return True

class ask_store:
    desc = "s:store"
    def __call__(self, spn, hpn):
        # XXX. store as log
        return True

# interactively committing modified files to the host
def interactive(box):

    menu = [ask_diff(), ask_view(), ask_ignore(), ask_commit(),
            ask_commitall(), ask_quit()]

    for root, dirs, files in os.walk(box.root):
        for name in files:
            spn = os.path.join(root, name)
            hpn = spn[len(box.root):]

            stop = False
            while not stop:
                print "> %s" % spn
                print "  [?]" + ", ".join(m.desc for m in menu) + "> ",
                c = util.kbhit()
                print ""
                for m in menu:
                    if m.desc.startswith(c+":"):
                        stop = m(spn, hpn)

# check pre/post condision of a test script
def check_pre(pn):
    return check("pre", pn, "N/A")

def check_post(pn, root):
    return check("post", pn, root)

def check(key, pn, root):
    cwd  = os.getcwd()
    spwd = util.chjoin(root, cwd)
    hpwd = cwd
    home = util.chjoin(root, os.path.expanduser("~"))
    for l in re.findall("#\s*%s:(.*)" % key, open(pn).read()):
        l = l.strip()
        l = l.replace("$SPWD"  , spwd)
        l = l.replace("$HPWD"  , hpwd)
        l = l.replace("$SHOME" , home)
        l = l.replace("$ROOT"  , root)
        if os.system(l) != 0:
            print "[!] %s: failed" % l
            return False
    return True
