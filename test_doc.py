#!/usr/bin/env python
from doctest import testfile, ELLIPSIS, testmod
from sys import exit, path as sys_path
from os.path import dirname

def testDoc(filename, name=None):
    print("--- %s: Run tests" % filename)
    failure, nb_test = testfile(
        filename, optionflags=ELLIPSIS, name=name)
    if failure:
        exit(1)
    print("--- %s: End of tests" % filename)

def importModule(name):
    mod = __import__(name)
    components = name.split('.')
    for comp in components[1:]:
        mod = getattr(mod, comp)
    return mod

def testModule(name):
    print("--- Test module %s" % name)
    module = importModule(name)
    failure, nb_test = testmod(module)
    if failure:
        exit(1)
    print("--- End of test")

def main():
    ptrace_dir = dirname(__file__)
    sys_path.append(ptrace_dir)

    # Test documentation in doc/*.rst files
    #testDoc('doc/c_tools.rst')

    # Test documentation of some functions/classes
    testModule("ptrace.compatibility")
    testModule("ptrace.tools")
    testModule("ptrace.signames")
    testModule("ptrace.logging_tools")
    testModule("ptrace.debugger.parse_expr")
    testModule("ptrace.syscall.socketcall")

if __name__ == "__main__":
    main()

