++++++++++++
PtraceSignal
++++++++++++


Introduction
============

PtraceSignal tries to display useful informations when a signal is received.
Depending on the signal number, it show different informations.

It uses the current instruction decoded as assembler code to understand why
the signal is raised.

Only Intel x86 (i386, maybe x86_64) is supported now.


Examples
========

Invalid read: ::

    Signal: SIGSEGV
    Invalid read from 0x00000008
    - instruction: MOV EAX, [EAX+0x8]
    - mapping: (no memory mapping)
    - register eax=0x00000000

Invalid write (MOV): ::

    Signal: SIGSEGV
    Invalid write to 0x00000008 (size=4 bytes)
    - instruction: MOV DWORD [EAX+0x8], 0x2a
    - mapping: (no memory mapping)
    - register eax=0x00000000

abort(): ::

    Signal: SIGABRT
    Program received signal SIGABRT, Aborted.

