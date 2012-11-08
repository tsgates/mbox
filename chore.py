import os
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

# interactively committing modified files to the host
def interactive(box):
    menu = [ask_diff(), ask_view(), ask_ignore(), ask_commit(), ask_quit()]
    for root, dirs, files in os.walk(box.root):
        for name in files:
            spn = os.path.join(root, name)
            hpn = spn.lstrip(box.root.rstrip("/"))

            stop = False
            while not stop:
                print "> %s" % spn
                print "  [?]" + ", ".join(m.desc for m in menu) + "> ",
                c = util.kbhit()
                print ""
                for m in menu:
                    if m.desc.startswith(c+":"):
                        stop = m(spn, hpn)
