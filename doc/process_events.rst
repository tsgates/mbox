Process events
==============

All process events are based on ProcessEvent class.

 * ProcessExit: process exited with an exitcode, killed by a signal
   or exited abnormally
 * ProcessSignal: process received a signal
 * NewProcessEvent: new process created, eg. after a fork() syscall

Attributes:

 * All events have a "process" attribute
 * ProcessExit has "exitcode" and "signum" attributes (both can be None)
 * ProcessSignal has "signum" and "name" attributes

For NewProcessEvent, use process.parent attribute to get the parent process.

Note: ProcessSignal has a display() method to display its content. Use it
just after receiving the message because it reads process memory to analyze
the reasons why the signal was sent.


Wait for any process event
==========================

The most generic function is waitProcessEvent(): it waits for any process
event (exit, signal or new process): ::

   event = debugger.waitProcessEvent()

To wait one or more signals, use waitSignals() methods. With no argument,
it waits for any signal. Events different than signal are raised as
Python exception. Examples: ::

   signal = debugger.waitSignals()
   signal = debugger.waitSignals(SIGTRAP)
   signal = debugger.waitSignals(SIGINT, SIGTERM)

Note: signal is a ProcessSignal object, use signal.signum to get
the signal number.


Wait for a specific process events
==================================

To wait any event from a process, use waitEvent() method: ::

   event = process.waitEvent()

To wait one or more signals, use waitSignals() method. With no argument,
it waits for any signal. Other process events are raised as Python
exception. Examples: ::

   signal = process.waitSignals()
   signal = process.waitSignals(SIGTRAP)
   signal = process.waitSignals(SIGINT, SIGTERM)

Note: As debugger.waitSignals(), signal is a ProcessSignal object.

