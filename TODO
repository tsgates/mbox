TODO
====

Main tasks
----------

 * Remove ptrace.ctypes_stdint
 * Fix strace.py --socketcall: SyscallState.enter() calls ignore_callback
   before socketcall are proceed
 * Support other backends:

    - GDB MI: http://code.google.com/p/pygdb/
    - ktrace: (FreeBSD and Darwin): would help Darwin support
    - utrace (new Linux debugger): http://sourceware.org/systemtap/wiki/utrace
    - vtrace?
    - PyDBG: works on Windows

 * Backtrace symbols:

   - GNU BFD?
   - elfsh?
   - addr2line program?
   - See dl_iterate_phdr() function of libdl

 * Support other disassemblers (than distorm), and so both Intel syntax (Intel and AT&T)

   - BFD
   - http://www.ragestorm.net/distorm/
   - libasm (ERESI)
   - libdisasm (bastard)
   - http://www.woodmann.com/collaborative/tools/index.php/Category:X86_Disassembler_Libraries

 * Support threads: other backends (than python-ptrace) already support threads

Minor tasks
-----------

 * setup.py: convert docstrings with 2to3 (run "2to3 -w -d ." ?)
 * Fix gdb.py "step" command on a jump. Example where step will never stop: ::

(gdb) where
ASM 0xb7e3b917: JMP 0xb7e3b8c4 (eb ab)
ASM 0xb7e3b919: LEA ESI, [ESI+0x0] (8db426 00000000)

 * Remove gdb.py "except PtraceError, err: if err.errno == ESRCH" hack,
   process death detection should be done by PtraceProcess or PtraceDebugger
 * Use Intel hardware breakpoints: set vtrace source code
 * Support Darwin:

   - ktrace? need to recompile Darwin kernel with KTRACE option
   - get registers: http://unixjunkie.blogspot.com/2006/01/darwin-ptrace-and-registers.html
   - PT_DENY_ATTACH: http://steike.com/code/debugging-itunes-with-gdb/
   - PT_DENY_ATTACH: http://landonf.bikemonkey.org/code/macosx/ptrace_deny_attach.20041010201303.11809.mojo.html

