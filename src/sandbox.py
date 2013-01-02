#!/usr/bin/env python2

import os
import sys
import re
import dbg
import pprint
import chore
import osbox
import util
import tracer

from optparse import OptionParser

def print_syscalls(opts):
    syscall.print_syscalls()
    
def parse_args():
    parser = OptionParser(usage="%prog [options] -- program [arg1 arg2 ...]")
    parser.add_option("--list-syscalls", "-l",
                      help="display system calls and exit",
                      action="store_true", default=None)
    parser.add_option("--strace", "-s",
                      help="print out system calls",
                      action="store_true", default=False)
    parser.add_option("--no-sandbox", "-n",
                      help="no sandboxing",
                      action="store_true", default=False)
    parser.add_option("-r", "--root",
                      help="root of the sandbox dir (ex /tmp/sandbox-%PID)",
                      default="/tmp/sandbox-%PID")
    parser.add_option("-C", "--cd",
                      help="change directory before executing the binary",
                      default=None)
    parser.add_option("-v", "--verbose",
                      help="verbose",
                      action="store_true", default=False)
    parser.add_option("-i", "--interact",
                      help="interactivly checking modified files",
                      action="store_true", default=False)
    parser.add_option("-t", "--test",
                      help="run as test, check pre/post conditions",
                      action="store_true", default=False)
    parser.add_option("-j", "--interpose",
                      help="interpose syscall using [ptrace, seccomp]",
                      default="ptrace")
    (opts, args) = parser.parse_args()

    # checking sanity
    if len(args) == 0 and not opts.list_syscalls:
        parser.print_help()
        exit(1)

    # control verbosity
    if not opts.verbose:
        dbg.quiet(dbg, ["error", "warn"])

    return (opts, args)

def parse_root(path):
    return path.replace("%PID", str(os.getpid()))

if __name__ == "__main__":
    (opts, args) = parse_args()

    if opts.list_syscalls:
        print_syscalls(opts)
        exit(1)

    # check pre condition when unit testing
    if opts.test:
        dbg.info("[!] checking %s" % args[0])
        if not chore.check_pre(args[0]):
            exit(1)

    # interpose opt
    if opts.interpose == "seccomp":
        interpose = tracer.TRACE_SECCOMP
    else:
        interpose = tracer.TRACE_PTRACE

    # change directory
    if opts.cd:
        os.chdir(opts.cd)

    # sandbox container
    box = osbox.OS(parse_root(opts.root))
    if opts.no_sandbox:
        tracer.trace(interpose, args, tracer.dump_syscall)
    else:
        tracer.trace(interpose, args, box.run)
    box.done()
    
    # interactively committing back to host
    if opts.interact:
        chore.interactive(box)

    # check post condition when unit testing
    if opts.test:
        dbg.info("[!] checking %s" % args[0])
        if not chore.check_post(args[0], box.root):
            exit(1)
