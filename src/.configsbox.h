#pragma once

//
// vm_writev() syscall allows us to invoke a single call to
// overwite memory of a remote process, but it can't overwrite
// the readonly area. To overwrite readonly memory, we will
// use ptrace poke if you don't explicitly enable this.
//
// #define SBOX_USE_WRITEV

//
// print debug messages, for fine control of messages, modify
// 'dbg.h' file.
// 
// #define SBOX_DEBUG
// 