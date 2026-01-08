
#define SYSCALL_PROLOGUE stp x0, x1, [sp, -16]! %% stp x2, x3, [sp, -16]! %% stp x4, x5, [sp, -16]! %% stp x6, x7, [sp, -16]!
#define SYSCALL_EPILOGUE ldp x6, x7, [sp], 16 %% ldp x4, x5, [sp], 16 %% ldp x2, x3, [sp], 16 %% ldp x0, x1, [sp], 16

#define DEF_SYSCALL(name, num)  .global _##name %% _##name: %% SYSCALL_PROLOGUE %% mov x16, num %% svc #0x80 %% mov x16, x0 %% SYSCALL_EPILOGUE %% bcc name##_end %% cmp x16, #4 %% beq _##name %% mov x16, #-1 %% name##_end: %% mov x0, x16 %% ret
#define DEF_MACHTRAP(name, num) .global _##name %% _##name: %% mov x16, -num %% svc #0x80 %% ret
#define DEF_ALIAS(to, from) .global _##to %% _##to: %% b _##from

.text
.align 4

.global _DYLD_HOOK_ENTRY
_DYLD_HOOK_ENTRY:
    // Copy-Paste from dyld
    mov    x0, sp
    mov    x19, sp
    and    sp, x0, #~15 // force 16-byte alignment of stack
    mov    fp, #0

    // Call init
    bl _dyldhook_init

    // Restore stack
    mov sp, x19

    // Jump to real start
    br x0


DEF_SYSCALL(__sandbox_ms, 381)

.data
.global ___stack_chk_guard
___stack_chk_guard:
    .quad 0x1337