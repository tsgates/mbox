# 
# dbg module
#  by Taesoo Kim
#  

import sys
import os

#
# dbg configuration
#
settings = {
    "test"      : True,
    "info"      : True,
    "parse"     : True,
    "error"     : True,
    }

#
# usage:
#
#    dbg.test("#B<red text#> = %s", error)
#    dbg.info("this is info")
#    dbg.error("this is #R<error#>")
# 
#    dbg.stop()  : invoke pdb
#    dbg.quiet() : suppressing dbg messages
#

#
# <<func>>   : function name
# <<line>>   : line number
# <<file>>   : file name
# <<tag>>    : tag name
# #B<        : blue
# #R<        : red
# #G<        : green
# #Y<        : yellow
# #C<        : cyan
# #>         : end mark
# 

header = "'[#B<%-18s#>] ' % (<<func>>)"

# reference color
BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, RESERVED, DEFAULT = range(10)

def currentframe() :
    try :
        raise Exception
    except :
        return sys.exc_traceback.tb_frame.f_back

def formatting(msg, tag, rv) :
    h = msg
    
    h = h.replace("<<tag>> ", tag)
    h = h.replace("<<func>>", repr(rv[2]))
    h = h.replace("<<line>>", repr(rv[1]))
    h = h.replace("<<file>>", repr(rv[0]))

    return coloring(eval(h))

def coloring(msg) :
    h = msg
    h = h.replace("#B<", "\033[3%dm" % BLUE)
    h = h.replace("#G<", "\033[3%dm" % GREEN)
    h = h.replace("#R<", "\033[3%dm" % RED)
    h = h.replace("#Y<", "\033[3%dm" % YELLOW)
    h = h.replace("#C<", "\033[3%dm" % CYAN)
    h = h.replace("#>" , "\033[m")
    return h

def dbg(tag, mark, *args):
    if not (tag in settings and settings[tag]) :
        return

    f = currentframe()
    
    # caller's frame
    if f is not None:
        f = f.f_back

    # look up frames
    rv = "(unknown file)", 0, "(unknown function)"
    while hasattr(f, "f_code"):
        co = f.f_code
        filename = os.path.normcase(co.co_filename)
        if filename in [__file__, "<string>"]:
            f = f.f_back
            continue
        rv = (filename, f.f_lineno, co.co_name)
        break

    if len(args) > 1:
        msg = str(args[0]) % args[1:]
    else:
        msg = str(args[0])
        
    sys.stderr.write(("%s%s %s\n" % (formatting(header, tag, rv),
                                     coloring(mark),
                                     coloring(msg))))

for k, v in settings.iteritems() :
    if v :
        exec("def %s(*msg) : dbg('%s',' ',*msg)" % (k, k))
        exec("def %sm(*msg): dbg('%s',*msg)"     % (k, k))
    else :
        exec("def %s(*msg) : pass" % k)
        exec("def %sm(*msg): pass" % k)

def fatal(*msg):
    dbg("fatal", ' ', *msg)
    exit(1)

def stop():
    import pdb
    pdb.Pdb().set_trace(sys._getframe().f_back)

def quiet(enable=[]):
        def ignore(*key, **kwds):
                pass
        for k in set(settings.keys()) - set(enable):
            exec("%s  = ignore", k)
            exec("%sm = ignore", k)