from ptrace.cpu_info import CPU_POWERPC, CPU_INTEL, CPU_X86_64, CPU_I386

CPU_INSTR_POINTER = None
CPU_STACK_POINTER = None
CPU_FRAME_POINTER = None
CPU_SUB_REGISTERS = {}

if CPU_POWERPC:
    CPU_INSTR_POINTER = "nip"
    # FIXME: Is it the right register?
    CPU_STACK_POINTER = 'gpr1'
elif CPU_X86_64:
    CPU_INSTR_POINTER = "rip"
    CPU_STACK_POINTER = "rsp"
    CPU_FRAME_POINTER = "rbp"
    CPU_SUB_REGISTERS = {
        # main register name, shift, mask
        'al':  ('rax', 0, 0xff),
        'bl':  ('rbx', 0, 0xff),
        'cl':  ('rcx', 0, 0xff),
        'dl':  ('rdx', 0, 0xff),
        'ah':  ('rax', 8, 0xff),
        'bh':  ('rbx', 8, 0xff),
        'ch':  ('rcx', 8, 0xff),
        'dh':  ('rdx', 8, 0xff),
        'ax':  ('rax', 0, 0xffff),
        'bx':  ('rbx', 0, 0xffff),
        'cx':  ('rcx', 0, 0xffff),
        'dx':  ('rdx', 0, 0xffff),
        'eax': ('rax', 32, None),
        'ebx': ('rbx', 32, None),
        'ecx': ('rcx', 32, None),
        'edx': ('rdx', 32, None),
    }
elif CPU_I386:
    CPU_INSTR_POINTER = "eip"
    CPU_STACK_POINTER = "esp"
    CPU_FRAME_POINTER = "ebp"
    CPU_SUB_REGISTERS = {
        'al': ('eax', 0, 0xff),
        'bl': ('ebx', 0, 0xff),
        'cl': ('ecx', 0, 0xff),
        'dl': ('edx', 0, 0xff),
        'ah': ('eax', 8, 0xff),
        'bh': ('ebx', 8, 0xff),
        'ch': ('ecx', 8, 0xff),
        'dh': ('edx', 8, 0xff),
        'ax': ('eax', 0, 0xffff),
        'bx': ('ebx', 0, 0xffff),
        'cx': ('ecx', 0, 0xffff),
        'dx': ('edx', 0, 0xffff),
    }

if CPU_INTEL:
    CPU_SUB_REGISTERS.update({
        'cf': ('eflags', 0, 1),
        'pf': ('eflags', 2, 1),
        'af': ('eflags', 4, 1),
        'zf': ('eflags', 6, 1),
        'sf': ('eflags', 7, 1),
        'tf': ('eflags', 8, 1),
        'if': ('eflags', 9, 1),
        'df': ('eflags', 10, 1),
        'of': ('eflags', 11, 1),
        'iopl': ('eflags', 12, 2),
    })

